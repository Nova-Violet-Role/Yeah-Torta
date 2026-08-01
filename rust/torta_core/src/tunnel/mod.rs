/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **THE RUST TUNNEL ENGINE** — the de-InviZible endgame: a pure-Rust tun-packet loop that replaces
//! the legacy C engine (`jni/invizible/*.c` + `libinvizible.so`) AND the Go binary
//! (`libs/libdnscrypt-proxy.so`). Rust reads packets from the VpnService tun fd, parses IP/UDP,
//! calls [`crate::resolver::resolve_datapath`] directly (no `dlsym`, no cross-library flag — spec §1),
//! and writes the reply back. No JNI, no C, no Go on this path.
//!
//! ## GENESIS — study → overhaul → combine → bind → awaken
//!
//! Studied (NEVER copy-pasted):
//! - **`tun-rs-main/`** — the cross-platform Rust TUN/TAP library. Resolves Q-ground-3 (Android
//!   tun-fd blocking semantics): the established pattern is a BLOCKING `read()` on the raw fd from
//!   a dedicated OS thread (the VpnService fd is established blocking; a `poll()` with a bounded
//!   timeout makes the read loop stop-responsive without `O_NONBLOCK` complexity). The loop here
//!   mirrors that — a dedicated thread, blocking read, periodic stop-flag check via `poll`.
//! - **`udp.c:478-498`** — the inline Rust-resolver bridge that became the WHOLE loop: parse the
//!   :53 UDP payload, call `torta_resolve`, write the reply back via `write_udp`. The Rust loop
//!   reproduces it natively, in-process (no `dlsym`).
//! - **`listener.rs:152-215`** — the Centauri-Mirror dedicated-OS-thread precedent (a named
//!   detached thread owns a fresh runtime + serves for the process lifetime). The loop thread
//!   mirrors its shape: `thread::Builder::name(...).spawn(move || loop {...})`.
//!
//! Combined: tun-rs (fd I/O shape) × udp.c (the DNS decision tree, in [`parse`]) × listener.rs
//! (the thread precedent) → the `tunnel/` module, dormant-until-wired (the listener.rs:75 idiom).
//!
//! ## The 4 Risk contracts (locked, spec §"LOCKED DECISIONS")
//!
//! - **R1 fd-handoff** — Kotlin calls `pfd.detachFd()` ONCE; Rust dups into an [`OwnedFd`], owns
//!   the DUP for the loop lifetime, closes the DUP on stop. NEITHER side ever closes the original
//!   int (the spec's one-fd-per-start safety —宁可 leak one fd than double-close).
//! - **R2 protect** — the [`ProtectCallback`] trait: `protect_fd(fd) -> bool`, Kotlin impls
//!   `vpnService.protect(fd)`, called BEFORE every upstream `connect()`/`sendto()`. The trait is
//!   DEFINED here; the loop itself does NOT open upstream sockets (the resolver does), so the
//!   protect HOOK lands in `resolver/dnscrypt.rs` / `doq.rs` / `doh3.rs` (task 1E). This module
//!   threads the callback through [`TunnelController`] so 1E can reach it from the resolver.
//! - **R3 RUNNING-signal** — arming the resolver at VPN-establish time is a Kotlin-side concern
//!   (task 1D); the loop calls [`crate::resolver::resolve_datapath`] which is a no-op when the
//!   resolver is unconfigured (returns `None` ⇒ the loop synthesizes SERVFAIL, R4).
//! - **R4 no-Go-fallback** — `resolve_datapath` returning `None` ⇒ synthesize SERVFAIL (rcode 2)
//!   via [`synth::synthesize_servfail`] and write it back. NEVER silently drop.
//!
//! ## Invariants
//!
//! **This module carries NO `allow(dead_code)`, and that is deliberate.** The doc here used to
//! state `#![cfg_attr(not(test), allow(dead_code))]` as a current invariant; measured 2026-07-31,
//! that attribute does not exist anywhere in this file (`grep -cE '^\s*#!?\[cfg_attr\(not\(test\),
//! *allow\(dead_code\)'` → **0**), and the crate-wide first-party count of real `allow(dead_code)`
//! attributes is likewise **0**. The comment was describing an attribute that had since been
//! removed — a doc asserting something false about the code beneath it, which is worse than no doc.
//!
//! The consequence is the honest one and must not be silenced again: this module ships **dormant**
//! (task 1B never wired the UniFFI exports, and `lib.rs` declares `mod tunnel;` PRIVATE), so every
//! item below is genuinely unreachable and rustc says so out loud — 55 dead-code warnings across
//! `parse.rs`/`synth.rs`/`warden.rs`/this file. That noise is the POINT: banning the allow converts
//! invisible rot into a worklist. Silencing it again would hide a whole ported subsystem.
//!
//! The pure logic ([`parse`], [`synth`], [`warden`]) is
//! cross-platform (host-testable); the fd I/O is unix-gated (the Windows host build skips it, so
//! `cargo build --lib` stays green without `libc` on non-unix). The loop uses `unsafe` ONLY for the
//! fd primitives (`dup`, `from_raw_fd`, `read`, `write`, `poll`) — every block has a SAFETY note.


pub mod parse;
pub mod synth;
pub mod warden;

// The re-exported surface for the future UniFFI exports (task 1B wires `TunnelController` etc. via
// `use crate::tunnel::{...}`). The module is dormant until then, so silence the unused-import lint
// for the non-test build (the listener.rs:75 dead-code-until-wired idiom).
#[allow(unused_imports)]
pub use parse::{IpAddrBytes, ParsedPacket, UdpLayer};
#[allow(unused_imports)]
pub use synth::{synth_ip_udp_reply, synthesize_servfail, RCODE_SERVFAIL};
#[allow(unused_imports)]
pub use warden::Verdict;

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ===================================================================================================
// R2 — the ProtectCallback trait. UniFFI callback-interface (Kotlin impls `vpnService.protect(fd)`).
// Task 1C DEFINES the surface; task 1E wires it into the resolver's upstream sockets.
// ===================================================================================================

/// The Risk-2 protect callback — the surface Kotlin implements as `vpnService.protect(fd)`. Called
/// from the resolver's upstream transports (DNSCrypt UDP/TCP, DoQ, DoH3) BEFORE every
/// `connect()`/`sendto()` so the upstream socket is excluded from the VpnService tun (else an
/// egress loop: the upstream packet re-enters the tun and the loop sees its own query).
///
/// `false` ⇒ the caller fail-fast skips that transport and tries the next. **Never proceed with an
/// unprotected socket** (the egress-loop invariant). The trait is `Send + Sync + 'static` so the
/// resolver (on its own runtime) can hold it across `await` points.
///
/// Task 1C defines the trait; task 1E adds the `protect_fd` call site in the transports and threads
/// an `Arc<dyn ProtectCallback>` from the [`TunnelController`] into the resolver's per-transport
/// state. Task 1B promoted the trait to a UniFFI callback-interface (`with_foreign`: the Kotlin side
/// provides the implementation — the Beast `BeastMetricSink` precedent, beast/mod.rs:179). The trait
/// is `Send + Sync` (no `'static` bound — `Arc<dyn ProtectCallback>` is object-lifetime-defaulted to
/// `'static`, matching `BeastMetricSink`).
#[uniffi::export(with_foreign)]
pub trait ProtectCallback: Send + Sync {
    /// Protect the given raw fd (call `VpnService.protect(fd)`). Returns `true` on success.
    fn protect_fd(&self, fd: i32) -> bool;
}

/// ★ N-WARDEN (#144) — the flow-owner UID resolver, the ONE fact the Warden verdict cannot rule
/// without: `torta_firewall_verdict` (lib.rs) ABSTAINs unconditionally on `uid < 0` (the fail-safe
/// guard against casting a negative uid), so a uid-less forwarder gate would be permanently dead.
/// Kotlin implements this as `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)`
/// (API 29+; returns `-1` below 29, on a SecurityException, or when the OS cannot attribute the
/// flow — never a fabricated uid). The forwarder calls it ONCE per accepted non-DNS flow (the uid
/// is a per-flow fact, not per-packet), on the flow task, before the upstream dial.
///
/// The same `with_foreign` callback-interface shape as [`ProtectCallback`] (task 1B precedent).
#[uniffi::export(with_foreign)]
pub trait UidResolver: Send + Sync {
    /// The uid owning the flow `src → dst`, or `-1` when unresolved. `protocol` is the IANA
    /// protocol number (6 TCP, 17 UDP); addresses are `inet` strings; ports host-order.
    fn uid_of(&self, protocol: i32, src_ip: String, src_port: u16, dst_ip: String, dst_port: u16)
        -> i32;
}

// ===================================================================================================
// TunnelConfig + TunnelStats + TunnelSnapshot — the controller's typed surface.
// ===================================================================================================

/// Sanitize the caller-supplied block rcode into a value that is BOTH expressible on the wire and
/// actually a refusal.
///
/// The previous `blocked_rcode.clamp(0, 255) as u8` was a FAIL-OPEN, and the reason is that the two
/// ends disagreed about the field's width. A DNS rcode is FOUR BITS: `apply_servfail_header`
/// (`synth.rs:108`) stamps `rcode & 0x0F`. So the clamp admitted 0..=255 and the mask then silently
/// folded anything above 15 onto an unrelated value — and `16` folded onto **0 = NOERROR**, which
/// tells the app the query SUCCEEDED. An operator asking for a stricter block got no block at all.
///
/// Both ends of the range are refused for the same reason, not out of tidiness:
/// - `0` (NOERROR) is not a refusal. A block that answers NOERROR is indistinguishable from success.
/// - `> 15` cannot be represented, and truncating it produces a DIFFERENT rcode than the operator
///   asked for — silently answering with a verdict nobody chose.
/// - `< 0` is a hostile or mistaken FFI integer.
///
/// All three fall back to [`RCODE_SERVFAIL`], which is a genuine refusal and is what the field's own
/// documented default already is. An operator's in-range choice (1..=15) is preserved EXACTLY.
/// ★ N-dial — the cause of a failed upstream dial, as a CLOSED set.
///
/// A partition, not a guess: every dial failure lands in exactly one variant. `Other` is the
/// deliberate catch-all that makes it total, so no error can ever be silently uncounted -- which is
/// precisely what the old `Err(_)` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialFailure {
    /// `ECONNREFUSED` -- the host answered and refused. Reachability is FINE; nothing is listening.
    Refused,
    /// `ENETUNREACH` / `EHOSTUNREACH` / `EAFNOSUPPORT` -- no route to the destination.
    Unreachable,
    /// `ETIMEDOUT` -- dropped in silence. Distinct from Refused: a firewall blackhole, not a refusal.
    TimedOut,
    /// Anything else, including local socket-setup failure before the network was ever touched.
    Other,
}

/// Classify a dial failure from its raw errno.
///
/// Takes the errno rather than an `io::Error` so the mapping is a pure total function of an integer
/// and can be reasoned about exhaustively -- `io::ErrorKind` is `#[non_exhaustive]` and its variants
/// are not stable to match on across platforms, which would make the partition unprovable.
///
/// `None` (no OS error behind the failure -- a tokio-level timeout, or a local setup error) is NOT
/// dropped: it maps to `Other`, keeping the classification TOTAL.
///
/// The errno numbers are the Linux/Android values, which is the only platform the forwarder builds
/// for (`upstream.rs` is UNIX-ONLY by its own module doc).
pub(crate) fn classify_dial_failure(raw_errno: Option<i32>) -> DialFailure {
    match raw_errno {
        Some(111) => DialFailure::Refused,     // ECONNREFUSED
        Some(101) => DialFailure::Unreachable, // ENETUNREACH
        Some(113) => DialFailure::Unreachable, // EHOSTUNREACH
        Some(97) => DialFailure::Unreachable,  // EAFNOSUPPORT -- no stack for this family
        Some(110) => DialFailure::TimedOut,    // ETIMEDOUT
        _ => DialFailure::Other,
    }
}

/// The largest tun MTU this datapath will ever accept.
///
/// The ERR_CONNECTION_CLOSED cause (checkpoint 58): the VPN builder shipped `VPN_MTU = 1500`,
/// equal to the underlying link MTU, leaving ZERO headroom. A full-size packet handed to the
/// tunnel exceeds the real path MTU once re-encapsulated and is silently dropped. Because the
/// failure is SIZE-dependent it read as site-dependent and hid for three weeks behind green DNS
/// instruments: DNS queries are 60-100 B and always fit, while a TLS handshake's certificate
/// records run 1400 B and up and are the FIRST full-size packet on a connection. Measured on the
/// same 111-URL Brave Nightly run, changing nothing but this: chromium
/// `ssl_client_socket_impl.cc:964 handshake failed` **704 -> 0**, `reset by peer` 24 -> 3.
///
/// 1400 is this repo's own safe value, already named at `NetworkChecker.kt:34`
/// (`DEFAULT_MTU = 1400`) and used there as the fallback when the link MTU cannot be read. It
/// leaves 100 B of headroom below a 1500 B Ethernet path and stays at or under the 1400-1450
/// MTUs common on mobile carriers and PPPoE links.
pub(crate) const TUN_MTU_CEILING: usize = 1400;

/// The smallest tun MTU the read loop can work with (a short buffer truncates packets).
pub(crate) const TUN_MTU_FLOOR: usize = 64;

/// Clamp a caller-supplied tun MTU into `[TUN_MTU_FLOOR, TUN_MTU_CEILING]`.
///
/// This exists because the previous code was `mtu.max(64)` — a FLOOR ONLY. Nothing stopped a
/// caller (or a hand edit to the Kotlin constant, which is exactly what happened) from asking for
/// 1500 and black-holing every large packet. A one-sided clamp on a value whose danger is being
/// TOO LARGE is not a guard at all. Now the dangerous direction is the one that cannot be
/// expressed: raising `VPN_MTU` back to 1500 by hand can no longer reach the datapath.
///
/// Negatives and zero fold to the floor rather than wrapping — the `as usize` cast on a negative
/// `i32` would otherwise produce an enormous buffer, which is the same class of bug in the
/// opposite direction.
///
/// PROVED FOR ALL `i32` in `D:/Lean/proofs/Proofs/TunMtuHeadroom.lean`:
/// `clamp_never_exceeds_ceiling`, `clamp_never_below_floor`, `clamp_is_idempotent`,
/// `clamp_fixes_the_shipped_defect`, `headroom_is_positive_under_the_ceiling`,
/// `clamp_is_monotone`, `no_input_can_reach_the_link_mtu`.
pub(crate) fn clamp_tun_mtu(requested: i32) -> usize {
    if requested <= TUN_MTU_FLOOR as i32 {
        TUN_MTU_FLOOR
    } else if (requested as usize) > TUN_MTU_CEILING {
        TUN_MTU_CEILING
    } else {
        requested as usize
    }
}

pub(crate) fn sanitize_blocked_rcode(requested: i32) -> u8 {
    if (1..=15).contains(&requested) {
        requested as u8
    } else {
        RCODE_SERVFAIL
    }
}

/// The loop's runtime configuration (the spec §2 `start(...)` parameters, typed). Set ONCE at
/// `start()` time and read by the loop thread for the loop's lifetime.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// The tun MTU (the read buffer size). The loop reads up to `mtu` bytes per packet.
    pub mtu: usize,
    /// The DNS rcode to stamp on a Warden-DENY'd DNS query (default [`RCODE_SERVFAIL`], 2).
    pub blocked_rcode: u8,
    /// `fwd53` — intercept packets to :53 (udp.c:213). When `false`, the loop short-circuits the
    /// DNS-intercept path (the `!fwd53` edge — udp.c:213-214).
    pub fwd53: bool,
    /// `bypass_lan` — skip LAN/mDNS suffixes (udp.c:449-466). When `true`, a qname matching the
    /// 13-suffix LAN list is dropped (left to the system resolver), not intercepted.
    pub bypass_lan: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            blocked_rcode: RCODE_SERVFAIL,
            fwd53: true,
            bypass_lan: true,
        }
    }
}

/// The loop's observed telemetry — counts ONLY (T20: no qname, no IP, no name ever). Mirrors
/// `listener.rs`'s `ListenerStats` discipline.
#[derive(Default)]
struct TunnelStats {
    /// Packets read off the tun (any version / proto).
    pkts_in: AtomicU64,
    /// DNS queries intercepted (UDP :53, fwd53, parsed).
    dns_intercepted: AtomicU64,
    /// Resolver answers written back.
    dns_answered: AtomicU64,
    /// SERVFAILs synthesized (resolver None, Risk 4).
    dns_servfail: AtomicU64,
    /// DNS queries the Warden DENIED by qname, answered with the operator's `blocked_rcode`.
    ///
    /// Deliberately NOT folded into `dropped` or `dns_servfail`: a policy refusal that we ANSWERED
    /// is a different event from a packet we discarded and from a transport failure, and the three
    /// want different operator responses. Counting them together would make a working per-name
    /// block look like packet loss.
    dns_warden_denied: AtomicU64,
    /// Packets dropped (Warden DENY, or a parse drop, or a write failure).
    dropped: AtomicU64,
    /// Read/write errors (a transient fd error — never fatal to the loop, counted + swallowed).
    io_errors: AtomicU64,
}

/// A snapshot of the loop telemetry (owned counts, safe across the FFI). Counts only; no qname, no
/// IP (T20). The shape mirrors `resolver::ListenerSnapshot`. Task 1B wired the UniFFI Record reader;
/// the fields are populated by [`TunnelController::snapshot`] and read by Kotlin.
#[derive(Clone, Copy, Debug, Default, uniffi::Record)]
pub struct TunnelSnapshot {
    pub pkts_in: u64,
    pub dns_intercepted: u64,
    pub dns_answered: u64,
    pub dns_servfail: u64,
    /// DNS queries refused by a Warden domain rule and ANSWERED with the operator's rcode —
    /// distinct from `dropped` (discarded) and `dns_servfail` (transport failure).
    pub dns_warden_denied: u64,
    pub dropped: u64,
    pub io_errors: u64,
    /// `true` while the loop thread is running.
    pub running: bool,
}

// ===================================================================================================
// ★ N6 (#144) — the FORWARDER telemetry surface: ForwarderStats (atomics) + ForwarderSnapshot (Record).
// Lives HERE (always compiled) rather than inside the netstack-gated `forwarder` module because the
// UniFFI surface must be ONE shape across feature sets (the generated .kt is shared — the same reason
// `set_netstack` exports ungated with a gated body): on a base .so the snapshot reads all-zero +
// `armed=false`/`live=false`; the netstack forwarder (when compiled AND armed) is the only writer.
// ===================================================================================================

/// The forwarder-plane telemetry — counts ONLY (T20 discipline: no qname, no IP, no port ever).
/// All-atomic: the accept loop + every per-flow task update lock-free, the snapshot reader is
/// wait-free. The controller owns ONE per lifetime; `spawn_netstack_forwarder` threads the `Arc`
/// into [`crate::forwarder::run_forwarder`], which is the sole writer.
#[derive(Default)]
pub(crate) struct ForwarderStats {
    /// `true` while the async forwarder loop is live (set at `run_forwarder` entry, cleared at exit) —
    /// the honest witness that the netstack fork actually took (vs. armed-but-declined → sync loop).
    pub(crate) live: AtomicBool,
    /// TCP flows accepted off the netstack (the page-load path).
    pub(crate) flows_tcp: AtomicU64,
    /// UDP flows accepted (incl. the `:53` DNS flows answered in-loop).
    pub(crate) flows_udp: AtomicU64,
    /// Unknown-transport flows dropped — everything the netstack yields that no arm claims. Since
    /// ★ #51 gave ICMPv4 echo its own lane, this is the genuine remainder (ICMPv6, IGMP, ESP, …),
    /// NOT "ping". A climbing count here now names protocols we have chosen not to carry.
    pub(crate) flows_other: AtomicU64,
    /// ★ #51 N9 — ICMPv4 ECHO REQUESTS accepted off the tun (every `ping` the device sends).
    pub(crate) icmp_echo: AtomicU64,
    /// ★ #51 N9 — echo requests that came back: a real reply from the real destination, measured
    /// through a protected unprivileged ping socket and written back into the tun. THE metric that
    /// matters — each one is a round trip the device actually completed while shielded.
    pub(crate) icmp_replied: AtomicU64,
    /// ★ #51 N9 — echo requests that produced no reply (timeout, unreachable, protect refusal, or a
    /// kernel that denies unprivileged ping sockets). Kept SEPARATE from [`Self::flows_other`]:
    /// "we tried and the network did not answer" is a different fact from "we do not carry this
    /// protocol", and conflating them would make an unreachable host look like a missing feature.
    pub(crate) icmp_failed: AtomicU64,
    /// Flows live RIGHT NOW (inc at flow spawn, dec at flow end — the gauge the CAKE fountain animates).
    pub(crate) active_flows: AtomicU64,
    /// Flows classified per Tortä tin at accept ([`crate::forwarder`] N5 `tin_for_flow`).
    pub(crate) tin_critical: AtomicU64,
    pub(crate) tin_high: AtomicU64,
    pub(crate) tin_normal: AtomicU64,
    /// `:53` queries answered in-loop via the sovereign resolver (DNS preserved — the North Star).
    pub(crate) dns_answered: AtomicU64,
    /// NORMAL-tin TCP flows put under the YeAH pacer (N5 `forward_tcp_paced`).
    pub(crate) paced_flows: AtomicU64,
    /// Bytes spliced client→upstream / upstream→client (all forwarded arms).
    pub(crate) bytes_up: AtomicU64,
    pub(crate) bytes_down: AtomicU64,
    /// Real-RTT samples fed to per-flow YeAH shapers (paced arm only).
    pub(crate) rtt_samples: AtomicU64,
    /// YeAH loss reactions on paced flows (write stalls/errors).
    pub(crate) stalls: AtomicU64,
    /// ★ N-warden — non-DNS flows the Warden DENIED (dropped, never dialed). Counts only (T20):
    /// the uid/destination that earned the deny is never recorded here.
    pub(crate) warden_denied: AtomicU64,
    /// The most recent paced-flow cwnd (1..16 segments) — the fountain's live window gauge.
    pub(crate) cwnd_last: AtomicI32,
    /// ★ #66-A — cloaked `:443` flows whose hostname was recovered from the TLS ClientHello
    /// (`forwarder::sni`). COUNT only (T20): WHICH host was peeked is a flow-local routing decision and
    /// is never recorded. This is the honest witness that the HTTPS seam is seeing traffic at all.
    pub(crate) centauri_sni_peeked: AtomicU64,
    /// ★ #66-A — peeked flows carried end-to-end to the GENUINE CDN (no MITM, authentic TLS). Every one
    /// of these is an asset that would have BROKEN under the pre-#66 port-blind hairpin.
    pub(crate) centauri_spliced: AtomicU64,
    /// ★ #66-A — peeked flows that could not be spliced: the host did not resolve, was blocked (the
    /// block correctly holds on the HTTPS leg too), or the protected dial failed.
    pub(crate) centauri_splice_failed: AtomicU64,
    /// ★ #66 — cloaked `:443` flows TERMINATED locally and served from the offline catalog. THE metric
    /// that matters: each one is an asset delivered from the user's own device, with the CDN never
    /// contacted. This is Centauri doing the thing Centauri is for.
    pub(crate) centauri_tls_served: AtomicU64,
    /// ★ #66 — cloaked `:443` flows whose local termination could not complete: the CA is not armed, the
    /// mirror is not listening, or (most commonly) the client does not trust the device CA yet.
    pub(crate) centauri_tls_failed: AtomicU64,
    /// ★ N-dial — the protected upstream dial was REFUSED BY THE VPN SEAM: `protect(fd)` returned
    /// false (`forwarder::upstream`), so the socket would have looped back into our own tun. The
    /// flow is dropped before any connect. A CLIMBING count here is not a network problem — it
    /// means `VpnService.protect()` is failing, and EVERY non-DNS flow dies while DNS (answered
    /// in-loop, never dialed) keeps working. That asymmetry is the signature to recognise.
    pub(crate) dial_protect_failed: AtomicU64,
    /// ★ N-dial — the protected dial reached the network and still failed: socket creation, the
    /// non-blocking switch, or the async `connect` itself. This is upstream reachability, NOT the
    /// VPN seam — kept as a SEPARATE counter from [`Self::dial_protect_failed`] precisely because
    /// the two demand opposite fixes and were previously indistinguishable (both were silent).
    pub(crate) dial_connect_failed: AtomicU64,

    // ★ N-dial CLASSIFIED. `dial_connect_failed` above is the TOTAL and stays exactly that, so the
    // existing panel tile keeps its meaning. These four say WHY, because the reason was previously
    // thrown away at `Err(_)` and the panel had to label every failure "DIAL unreachable" whether
    // the peer refused us, the route was missing, or the handshake timed out. Those three demand
    // completely different fixes and were indistinguishable.
    //
    // Measured on a real AVD run: 1321 failures out of 1778 TCP flows with no way to tell which
    // kind, while pages that DID load proved the tunnel itself was fine.
    //
    // The four are a PARTITION of every dial failure -- total (every error lands somewhere) and
    // disjoint (never two buckets for one error), so refused + unreachable + timed_out + other
    // always equals the total. That invariant is proved in D:/Lean/proofs/Proofs/DialFailure.lean
    // rather than merely tested, because it must hold for EVERY errno the kernel can hand back.
    /// Peer actively said no (`ECONNREFUSED`) -- the host is up and reachable, nothing is listening.
    pub(crate) dial_refused: AtomicU64,
    /// No route / network or host unreachable (`ENETUNREACH`, `EHOSTUNREACH`, `EAFNOSUPPORT`).
    pub(crate) dial_unreachable: AtomicU64,
    /// The dial ran out of time (`ETIMEDOUT`, or a tokio timeout) -- silent drop, not a refusal.
    pub(crate) dial_timed_out: AtomicU64,
    /// Everything else, including local socket-setup failures (fd exhaustion, non-blocking switch).
    /// Kept as an explicit bucket so the partition is TOTAL rather than lossy.
    pub(crate) dial_other: AtomicU64,
    /// Dials TORTA DECLINED to make because the IPv6 latch is set. NOT a network measurement: the
    /// kernel was never asked, so no errno exists. These used to be counted as `dial_unreachable`,
    /// which reported "the network has no route" for a POLICY decision -- 126 of them on one AVD
    /// run beside 5 genuinely refused. A suppression and an unreachable network need different
    /// fixes, so they need different counters.
    pub(crate) dial_v6_suppressed: AtomicU64,

    // ★ N-dial-UDP — the SAME blind spot, on the protocol nobody was watching.
    //
    // `connect_tcp_protected` was taught to witness every failure exit; `connect_udp_protected` was
    // not, and kept FIVE silent `None` returns (socket create, protect refusal, the non-blocking
    // switch, `connect`, and the tokio handover). A UDP dial that failed moved no counter anywhere and
    // logged itself as `forward_tcp: connect_tcp_protected failed` -- wrong function AND wrong helper.
    //
    // That combination is worse than the original TCP bug it mirrors, because for a browser UDP IS
    // HTTP/3: when QUIC dials fail invisibly the page still often loads over the TCP fallback, so the
    // symptom is intermittent slowness and the occasional dead request rather than a clean failure --
    // and every log line points the investigator at TCP, which is working.
    //
    // The two totals stay SEPARATE per protocol (that is the whole diagnostic value: HTTP/3 vs
    // HTTP/2), while the four buckets above remain SHARED, because `classify_dial_failure` maps an
    // errno and an errno does not care which transport produced it. So the proved invariant widens to
    // refused + unreachable + timed_out + other == dial_connect_failed + udp_dial_connect_failed.
    /// `protect()` refused a UDP fd — the VpnService seam, exactly as [`Self::dial_protect_failed`].
    pub(crate) udp_dial_protect_failed: AtomicU64,
    /// A protected UDP dial reached the network and still failed. TOTAL for UDP; the WHY lands in the
    /// four shared buckets above.
    pub(crate) udp_dial_connect_failed: AtomicU64,
}

// ===================================================================================================
// ★ #47 N8 — THE PER-FLOW DOCKET. Everything above this line is an AGGREGATE: `active_flows` says
// HOW MANY flows are live but nothing about any ONE of them, so no panel can show a flow being
// shaped. The docket is the per-flow twin — one row per live flow, carrying that flow's own CAKE
// key, tin, window and byte counts.
//
// THE T20 LINE IS HELD. The module contract above is absolute ("no qname, no IP, no port ever"), and
// a per-flow view is exactly where that law is easiest to break. So a row carries NO address, NO
// port and NO hostname — only:
//   - `key`: the widened CAKE key (`forwarder::shape::flow_key`), a folded 64-bit hash. It is an
//     IDENTITY, not an address: it lets the panel follow one row as it evolves, and it is not an
//     endpoint any more than a hash is its input.
//   - `tin`: the DiffServ class the flow was already counted under in aggregate (tin_critical/high/
//     normal) — no new information is disclosed by attributing it to a row.
//   - the engine numbers: cwnd, bytes, rtt, stalls, age.
// The destination that would name the flow never enters this struct.
//
// LIFETIME. Rows are owned as `Arc<FlowLive>`: the forwarder's per-flow task holds one and updates
// it with RELAXED ATOMICS (no lock on the datapath — a mutex per spliced byte would be a
// bufferbloat engine of our own making), while the registry holds the other for enumeration. The
// task releases its row when the flow ends, so the docket tracks live flows only.
// ===================================================================================================

/// The docket capacity. A row is ~64 bytes, so 256 rows is a bounded ~16 KiB — and no panel renders
/// more than a screenful anyway. When full, registration is REFUSED rather than evicting a live
/// flow: the panel compares `docket.len()` against `active_flows` and says "N of M shown", which is
/// honest, instead of showing a silently truncated list that looks complete.
pub(crate) const FLOW_DOCKET_CAP: usize = 256;

/// ONE live flow's mutable state, shared between its forwarder task and the docket reader.
pub(crate) struct FlowLive {
    /// The widened CAKE key (`forwarder::shape::flow_key`) — an opaque folded hash, never an address.
    pub(crate) key: i64,
    /// The IANA protocol number — 6 TCP · 17 UDP · 1 ICMPv4. The proto is a transport CLASS, not an
    /// endpoint, so it discloses nothing (T20 holds).
    ///
    /// ★ #51 widened this from a `proto_tcp: bool`. A boolean can carry two protocols; the moment
    /// ICMP earned a lane it could carry three only by lying — every ping would have rendered as
    /// "UDP" because the flag was false. The number is the vocabulary the codebase already speaks
    /// (`forwarder::session::Proto::ip_number`), so the docket now names the protocol instead of
    /// negating one.
    pub(crate) proto: i32,
    /// 0 = CRITICAL (DNS plane), 1 = HIGH (interactive), 2 = NORMAL (bulk) — the N5 tin.
    pub(crate) tin: i32,
    /// This flow is under the YeAH pacer (NORMAL tin). CRITICAL/HIGH run unshaped, latency-first.
    pub(crate) paced: bool,
    /// Monotonic birth stamp — `age_ms` is derived at snapshot, so no clock is stored in the row.
    pub(crate) born: std::time::Instant,
    /// Live YeAH window (segments). 0 until the first update; unpaced flows stay 0 honestly.
    pub(crate) cwnd: AtomicI32,
    pub(crate) bytes_up: AtomicU64,
    pub(crate) bytes_down: AtomicU64,
    /// Most recent real RTT sample (ms), -1 before the first — the empty-state law: an unmeasured
    /// number must be distinguishable from a measured zero.
    pub(crate) rtt_ms: AtomicI32,
    /// YeAH loss reactions on THIS flow.
    pub(crate) stalls: AtomicU64,
}

impl FlowLive {
    /// Birth an unmeasured row: no window, no bytes, `rtt_ms = -1` (never "0 ms", which would read
    /// as a measured instant round trip).
    pub(crate) fn new(key: i64, proto: i32, tin: i32, paced: bool) -> Self {
        Self {
            key,
            proto,
            tin,
            paced,
            born: std::time::Instant::now(),
            cwnd: AtomicI32::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            rtt_ms: AtomicI32::new(-1),
            stalls: AtomicU64::new(0),
        }
    }

    /// Read this row into its wire twin.
    pub(crate) fn row(&self) -> ForwarderFlowRow {
        ForwarderFlowRow {
            key: self.key,
            proto: self.proto,
            tin: self.tin,
            paced: self.paced,
            cwnd: self.cwnd.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            rtt_ms: self.rtt_ms.load(Ordering::Relaxed),
            age_ms: self.born.elapsed().as_millis().min(u64::MAX as u128) as u64,
            stalls: self.stalls.load(Ordering::Relaxed),
        }
    }
}

/// Turn a MEASURED elapsed time in milliseconds into the per-flow docket's display integer.
///
/// ## The contract this exists to keep
///
/// `forwarder_dashboard.slint:44` declares the docket's three-state encoding:
///
/// ```text
/// rtt-ms: int,   // -1 = UNMEASURED (no paced write has completed yet), never rendered as 0
/// ```
///
/// and `:215` renders `rtt-ms >= 0` as a number and anything below as `rtt —`. So the panel has
/// exactly three states: `-1` unmeasured, `>= 1` measured, and `0` — which the contract asserts
/// CANNOT HAPPEN.
///
/// ## It happened
///
/// Both sample sites collapsed a real sub-millisecond round trip onto exactly that forbidden
/// value, and the AVD rendered `rtt 0ms` on a live TCP flow:
///
/// * `forwarder/run.rs` stored `rtt_ms.round() as i32` — anything under 0.5 ms ROUNDS to 0.
/// * `forwarder/icmp.rs` stored `elapsed().as_millis()` — which TRUNCATES, so anything under
///   1.0 ms becomes 0. Strictly worse: it eats twice the range.
///
/// A reader cannot tell "0 ms" apart from "no reading". It looks like the unpopulated tile it is
/// not: the flow moved 998 B and lived 23 s, so the transport plainly worked. That is the
/// silent-zero failure again, and the panel already had the vocabulary to avoid it.
///
/// ## The fix, and why a floor rather than a wider type
///
/// Floor a POSITIVE sample at 1. `1ms` then reads as "one millisecond or faster", `0` becomes
/// unreachable from any real measurement, and the three states stay distinct. Sub-millisecond
/// precision is not display-relevant on a docket that also shows `age 23s`; the DISTINCTION
/// between "fast" and "unknown" very much is. This is the same floor-at-one law already proved
/// for the cache in `LocalTtlClamp.lean` (`local_ttl_is_never_zero`).
///
/// A negative or non-finite input is carried to `-1` (UNMEASURED) rather than clamped upward: a
/// clock that ran backwards is not a fast round trip, and claiming `1ms` for it would fabricate a
/// measurement. `NaN` fails every comparison, so it is matched explicitly instead of by ordering.
///
/// Proved for ALL inputs in `D:/Lean/proofs/Proofs/RttDisplay.lean`.
pub(crate) fn rtt_display_ms(raw_ms: f64) -> i32 {
    if !raw_ms.is_finite() || raw_ms < 0.0 {
        return -1;
    }
    let rounded = raw_ms.round();
    if rounded >= i32::MAX as f64 {
        return i32::MAX;
    }
    // The floor: a real sample is never allowed to land on the reserved 0.
    (rounded as i32).max(1)
}

/// The live-flow registry. `Mutex<Vec<..>>` and NOT a lock-free map on purpose: it is touched twice
/// per FLOW (register, release), never per packet, so the lock is off the datapath entirely.
static FLOW_DOCKET: Mutex<Vec<Arc<FlowLive>>> = Mutex::new(Vec::new());

/// Enroll a live flow. Returns `false` when the docket is at [`FLOW_DOCKET_CAP`] — the caller keeps
/// forwarding regardless (telemetry NEVER gates the datapath), the flow simply goes unlisted.
pub(crate) fn docket_register(row: &Arc<FlowLive>) -> bool {
    let Ok(mut d) = FLOW_DOCKET.lock() else {
        return false; // a poisoned telemetry lock must not take the forwarder down with it
    };
    if d.len() >= FLOW_DOCKET_CAP {
        return false;
    }
    d.push(Arc::clone(row));
    true
}

/// Retire a flow's row by identity (pointer), NOT by key: two live flows can collide on a folded
/// hash, and removing "a row with this key" could retire the wrong one.
pub(crate) fn docket_release(row: &Arc<FlowLive>) {
    if let Ok(mut d) = FLOW_DOCKET.lock() {
        d.retain(|r| !Arc::ptr_eq(r, row));
    }
}

/// Enumerate every live flow. Wait-free for the datapath (the tasks never block on this lock).
pub(crate) fn docket_rows() -> Vec<ForwarderFlowRow> {
    match FLOW_DOCKET.lock() {
        Ok(d) => d.iter().map(|r| r.row()).collect(),
        Err(_) => Vec::new(),
    }
}

/// ONE live flow as the FORWARDER dashboard renders it — the per-flow twin of [`ForwarderSnapshot`].
/// Counts and classes only: no address, no port, no hostname (T20).
#[derive(Clone, Copy, Debug, Default, PartialEq, uniffi::Record)]
pub struct ForwarderFlowRow {
    /// The widened CAKE key — a folded 64-bit identity for the flow, never an address.
    pub key: i64,
    /// The IANA protocol number: **6** TCP · **17** UDP · **1** ICMPv4 (★ #51). A transport class,
    /// never an endpoint. Widened from a boolean the moment a third protocol earned a lane — a flag
    /// can only carry three states by misreporting one of them.
    pub proto: i32,
    /// 0 = CRITICAL (DNS plane) · 1 = HIGH (interactive) · 2 = NORMAL (bulk).
    pub tin: i32,
    /// Under the YeAH pacer (NORMAL tin only).
    pub paced: bool,
    /// Live YeAH window in segments; 0 on an unpaced flow (honestly unshaped, not "window zero").
    pub cwnd: i32,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Last real RTT sample (ms), or -1 when the flow has not been measured yet.
    pub rtt_ms: i32,
    /// Milliseconds since the flow was accepted.
    pub age_ms: u64,
    /// YeAH loss reactions on this flow.
    pub stalls: u64,
}

impl ForwarderStats {
    /// One coherent read of every counter (Relaxed — counts-only telemetry, same as
    /// [`TunnelController::snapshot`]). `armed` is supplied by the caller (the toggle is
    /// controller-side state, not forwarder-side).
    pub(crate) fn snapshot_with(&self, armed: bool) -> ForwarderSnapshot {
        ForwarderSnapshot {
            armed,
            live: self.live.load(Ordering::Relaxed),
            flows_tcp: self.flows_tcp.load(Ordering::Relaxed),
            flows_udp: self.flows_udp.load(Ordering::Relaxed),
            flows_other: self.flows_other.load(Ordering::Relaxed),
            icmp_echo: self.icmp_echo.load(Ordering::Relaxed),
            icmp_replied: self.icmp_replied.load(Ordering::Relaxed),
            icmp_failed: self.icmp_failed.load(Ordering::Relaxed),
            active_flows: self.active_flows.load(Ordering::Relaxed),
            tin_critical: self.tin_critical.load(Ordering::Relaxed),
            tin_high: self.tin_high.load(Ordering::Relaxed),
            tin_normal: self.tin_normal.load(Ordering::Relaxed),
            dns_answered: self.dns_answered.load(Ordering::Relaxed),
            paced_flows: self.paced_flows.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            rtt_samples: self.rtt_samples.load(Ordering::Relaxed),
            stalls: self.stalls.load(Ordering::Relaxed),
            warden_denied: self.warden_denied.load(Ordering::Relaxed),
            cwnd_last: self.cwnd_last.load(Ordering::Relaxed),
            centauri_sni_peeked: self.centauri_sni_peeked.load(Ordering::Relaxed),
            centauri_spliced: self.centauri_spliced.load(Ordering::Relaxed),
            centauri_splice_failed: self.centauri_splice_failed.load(Ordering::Relaxed),
            centauri_tls_served: self.centauri_tls_served.load(Ordering::Relaxed),
            centauri_tls_failed: self.centauri_tls_failed.load(Ordering::Relaxed),
            dial_protect_failed: self.dial_protect_failed.load(Ordering::Relaxed),
            dial_connect_failed: self.dial_connect_failed.load(Ordering::Relaxed),
            dial_refused: self.dial_refused.load(Ordering::Relaxed),
            dial_unreachable: self.dial_unreachable.load(Ordering::Relaxed),
            dial_timed_out: self.dial_timed_out.load(Ordering::Relaxed),
            dial_other: self.dial_other.load(Ordering::Relaxed),
            dial_v6_suppressed: self.dial_v6_suppressed.load(Ordering::Relaxed),
            udp_dial_protect_failed: self.udp_dial_protect_failed.load(Ordering::Relaxed),
            udp_dial_connect_failed: self.udp_dial_connect_failed.load(Ordering::Relaxed),
        }
    }
}

/// One live forwarder snapshot — the COMPLETE N6 metric surface the CAKE-fountain card renders
/// (the [`BeastSnapshot`](crate::beast::BeastSnapshot) discipline: every field a real engine read,
/// never a fabricated metric). Counts only, no qname/IP/port (T20). All-zero with `armed=false`
/// on a base (non-netstack) `.so` — the card renders DORMANT honestly.
#[derive(Clone, Copy, Debug, Default, PartialEq, uniffi::Record)]
pub struct ForwarderSnapshot {
    /// The runtime toggle ([`TunnelController::set_netstack`]) — armed for the NEXT start.
    pub armed: bool,
    /// The async forwarder loop is live right now (the fork actually took this start).
    pub live: bool,
    pub flows_tcp: u64,
    pub flows_udp: u64,
    /// Flows no arm claims (ICMPv6, IGMP, ESP, …). Since ★ #51 this EXCLUDES ICMPv4 echo, which
    /// has its own lane below — "dropped" here means "not carried", never "ping".
    pub flows_other: u64,
    /// ★ #51 N9 — ICMPv4 echo requests accepted (pings the device sent).
    pub icmp_echo: u64,
    /// ★ #51 N9 — echo requests answered by the real destination through a protected ping socket.
    pub icmp_replied: u64,
    /// ★ #51 N9 — echo requests that never came back (timeout/unreachable/refused).
    pub icmp_failed: u64,
    pub active_flows: u64,
    pub tin_critical: u64,
    pub tin_high: u64,
    pub tin_normal: u64,
    pub dns_answered: u64,
    pub paced_flows: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub rtt_samples: u64,
    pub stalls: u64,
    /// ★ N-warden — non-DNS flows the Warden DENIED (dropped before the upstream dial).
    pub warden_denied: u64,
    pub cwnd_last: i32,
    /// ★ #66-A — cloaked `:443` flows named via their TLS SNI (counts only, never the host).
    pub centauri_sni_peeked: u64,
    /// ★ #66-A — named flows carried end-to-end to the genuine CDN with authentic TLS.
    pub centauri_spliced: u64,
    /// ★ #66-A — named flows that could not be spliced (unresolved, blocked, or dial failure).
    pub centauri_splice_failed: u64,
    /// ★ #66 — cloaked :443 flows served LOCALLY from the offline catalog (CDN never contacted).
    pub centauri_tls_served: u64,
    /// ★ #66 — local termination that could not complete (CA unarmed, mirror down, or client distrusts the CA).
    pub centauri_tls_failed: u64,
    /// ★ N-dial — upstream dials refused by `VpnService.protect()`. Climbing ⇒ the VPN seam, not
    /// the network: every non-DNS flow dies silently while in-loop DNS still answers.
    pub dial_protect_failed: u64,
    /// ★ N-dial — upstream dials that failed at socket/connect time. Climbing ⇒ reachability.
    /// This is the TOTAL; the four fields below partition it by cause.
    pub dial_connect_failed: u64,
    /// ★ N-dial classified — peer refused (`ECONNREFUSED`): reachable host, no listener.
    pub dial_refused: u64,
    /// ★ N-dial classified — no route (`ENETUNREACH` / `EHOSTUNREACH` / `EAFNOSUPPORT`).
    pub dial_unreachable: u64,
    /// Dials declined by the IPv6 latch — a POLICY count, never a network measurement.
    pub dial_v6_suppressed: u64,
    /// ★ N-dial classified — timed out (`ETIMEDOUT`): the dial was dropped in silence.
    pub dial_timed_out: u64,
    /// ★ N-dial classified — anything else, incl. local socket-setup failure. Never empty by
    /// construction: it is the catch-all that makes the four a TOTAL partition.
    ///
    /// NOTE the partition is over BOTH totals: the four buckets are shared by TCP and UDP, so
    /// refused + unreachable + timed_out + other == dial_connect_failed + udp_dial_connect_failed.
    pub dial_other: u64,
    /// ★ N-dial-UDP — `protect()` refused a UDP fd. Same seam meaning as `dial_protect_failed`.
    pub udp_dial_protect_failed: u64,
    /// ★ N-dial-UDP — protected UDP dials that failed at socket/connect time. For a browser this is
    /// HTTP/3: climbing here with `dial_connect_failed` flat means QUIC is dying while TCP carries the
    /// page, which reads as intermittent slowness rather than a clean error.
    pub udp_dial_connect_failed: u64,
}

/// The TunnelController — owns the loop thread + the stop signal + the OwnedFd (the dup) + the
/// stats. One controller per VpnService establish; `stop()` joins the thread + closes the dup.
/// Task 1B lifted it to a `#[derive(uniffi::Object)]`: Kotlin holds an `Arc<TunnelController>`
/// constructed via [`tunnel_create`] (lib.rs) and drives start/stop/snapshot through the Object
/// surface (the Beast/Centauri/MaskSolver `uniffi::Object` precedent).
#[derive(uniffi::Object)]
pub struct TunnelController {
    /// The stop signal — set to `false` by [`TunnelController::stop`], polled by the loop thread
    /// every `POLL_TIMEOUT_MILLIS` (so stop is responsive without an O_NONBLOCK dance).
    running: Arc<AtomicBool>,
    /// The loop thread's JoinHandle (joined on stop). Read on unix (the loop is unix-gated); on a
    /// non-unix host build it is present-but-unread, hence the targeted allow.
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// The stats (shared between the loop thread + the snapshot reader).
    stats: Arc<TunnelStats>,
    /// ★ N6 (#144) — the forwarder-plane stats (shared between the netstack forwarder + the
    /// [`Self::forwarder_snapshot`] reader). Always present (cheap atomics); all-zero unless the
    /// netstack forwarder ran.
    fwd_stats: Arc<ForwarderStats>,
    /// The Risk-2 protect callback (threaded to 1E; held here so the resolver can reach it). Stored
    /// as `Option` so a `start` without a Kotlin callback (e.g. a test) does not block the API.
    protect: Mutex<Option<Arc<dyn ProtectCallback>>>,
    /// ★ N-warden — the flow-owner UID resolver (Kotlin's `ConnectivityManager` lookup), threaded
    /// into the netstack forwarder so the Warden verdict rules on a REAL uid. `None` (never
    /// installed) ⇒ every gate call passes `uid = -1` ⇒ the C-ABI ABSTAINs — fail-safe pass.
    uid_resolver: Mutex<Option<Arc<dyn UidResolver>>>,
}

// Internal helpers (NOT exposed to Kotlin — task 1E's plumbing into the resolver transports).
// Kept in a plain `impl` so the `#[uniffi::export] impl` below surfaces ONLY the Kotlin contract
// (start/stop/snapshot/is_running + the constructor). The Beast `attach_sink`/sink-arc precedent.
impl TunnelController {
    /// Install the Risk-2 protect callback. Task 1E retrieves it (or shares the Arc) into the
    /// resolver's transport layer so the upstream sockets call `protect_fd` before connect/sendto.
    pub fn set_protect_callback(&self, cb: Arc<dyn ProtectCallback>) {
        *self.protect.lock().unwrap() = Some(cb);
    }

    /// A clone of the protect callback Arc, if installed (1E calls this to thread the callback into
    /// the resolver). `None` when no Kotlin callback is wired yet.
    pub fn protect_callback(&self) -> Option<Arc<dyn ProtectCallback>> {
        self.protect.lock().unwrap().clone()
    }

    /// Build the inner state (shared by the constructor + `Default`).
    fn build() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            join: Mutex::new(None),
            stats: Arc::new(TunnelStats::default()),
            fwd_stats: Arc::new(ForwarderStats::default()),
            protect: Mutex::new(None),
            uid_resolver: Mutex::new(None),
        }
    }
}

// ===================================================================================================
// Task 1B — the UniFFI Object surface. Kotlin holds an `Arc<TunnelController>` (constructed via
// `tunnel_create` in lib.rs, OR the `new` constructor) and drives the lifecycle through these
// methods. The `start` signature is the spec §"LOCKED DECISIONS" Kotlin→Rust contract: the tun fd
// (R1 detachFd), the loop args, and the Risk-2 `ProtectCallback` callback-interface.
// ===================================================================================================

#[uniffi::export]
impl TunnelController {
    /// Construct a fresh controller (no loop running). Kotlin constructs one per VpnService
    /// establish — equivalently, [`crate::tunnel_create`] is the free-function twin. Returns an
    /// `Arc` so the Object is shared by reference across Kotlin holders (the Beast `new` precedent).
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::build())
    }

    /// **The Kotlin→Rust fd handoff + loop launch (Risks 1 + 2).** Mirrors the spec §2 `start(...)`
    /// signature: `tun_fd` (the detached int), `mtu`, `virtual_dns_ip`, `blocked_rcode`,
    /// `bypass_lan`, and the `protect_cb` callback-interface. Installs the protect callback FIRST
    /// (R2 — the resolver's upstream sockets reach it via [`Self::protect_callback`] before the
    /// first packet triggers a connect), builds the [`TunnelConfig`], then dispatches to the
    /// unix-gated loop. On a non-unix host (the Windows host build) returns `false` — no tun loop.
    ///
    /// Idempotent: a second `start` while running is a no-op (returns `false`). Returns `true` when
    /// the loop thread was spawned.
    #[allow(unused_variables)]
    pub fn start(
        &self,
        tun_fd: i32,
        mtu: i32,
        virtual_dns_ip: String,
        blocked_rcode: i32,
        bypass_lan: bool,
        protect_cb: Arc<dyn ProtectCallback>,
    ) -> bool {
        // R2: install the protect callback BEFORE the loop spawns so it is live when the first
        // upstream connect fires. TWO installs are required (measured 2026-07-04 on a networked AVD —
        // without the SECOND, the resolver's upstream DNSCrypt socket was NOT protect()'d, re-entered
        // the tun (0.0.0.0/0 → tun0), looped, and died → every query SERVFAILed → "unknown host"):
        //  (1) self.protect — the controller's own handle (held for stop/lifecycle).
        //  (2) crate::resolver::dnscrypt::install_protect_callback — the PROCESS-GLOBAL that
        //      resolver/dnscrypt.rs::protect_socket_before_connect actually reads (udp_exchange:636,
        //      tcp_exchange). Without this, protect_raw_fd is a no-op and the upstream egress-loops.
        *self.protect.lock().unwrap() = Some(protect_cb.clone());
        crate::resolver::dnscrypt::install_protect_callback(Some(protect_cb));

        // virtual_dns_ip: Stage-2-min intercepts ALL UDP :53 (the tun is the only egress); the
        // virtual IP is informational, retained for future per-IP filtering (Stage-3). No-op for now.
        let _ = virtual_dns_ip.as_str();

        let cfg = TunnelConfig {
            mtu: clamp_tun_mtu(mtu),
            blocked_rcode: sanitize_blocked_rcode(blocked_rcode),
            fwd53: true,
            bypass_lan,
        };

        #[cfg(unix)]
        {
            self.start_unix(tun_fd, cfg)
        }
        #[cfg(not(unix))]
        {
            false // no tun loop on a non-unix host
        }
    }

    /// Stop the loop: signal the stop flag, join the thread, drop the OwnedFd (closes the dup). The
    /// original `tun_fd` int (Kotlin-side) is untouched (R1 — neither side closes the original).
    pub fn stop(&self) {
        #[cfg(unix)]
        {
            self.stop_unix();
        }
    }

    /// A counts-only telemetry snapshot (T20 — no qname, no IP). The UniFFI Record reader is wired
    /// (task 1B); `port`-equivalent `running` flag is `true` while the loop thread is alive.
    pub fn snapshot(&self) -> TunnelSnapshot {
        TunnelSnapshot {
            pkts_in: self.stats.pkts_in.load(Ordering::Relaxed),
            dns_intercepted: self.stats.dns_intercepted.load(Ordering::Relaxed),
            dns_answered: self.stats.dns_answered.load(Ordering::Relaxed),
            dns_servfail: self.stats.dns_servfail.load(Ordering::Relaxed),
            dns_warden_denied: self.stats.dns_warden_denied.load(Ordering::Relaxed),
            dropped: self.stats.dropped.load(Ordering::Relaxed),
            io_errors: self.stats.io_errors.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
        }
    }

    /// `true` while the loop thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// ★ NETSTACK GENESIS (#144) — arm/disarm the pure-Rust TCP/UDP forwarder (Kotlin's netstack toggle).
    /// When ON, the NEXT `start` runs the ipstack forwarder (carries non-DNS traffic OUT so DNSCrypt resolves
    /// PAGES, answering `:53` inline via DNSCrypt) instead of the sync DNS-only loop. Takes effect on the next
    /// VpnService establish — an in-flight loop is not hot-swapped. On a `.so` built WITHOUT the `netstack`
    /// feature this is a no-op (the forwarder code is not compiled) — the byte-clean-base discipline. The
    /// resolver stays sovereign either way (DNS is always DNSCrypt).
    #[allow(unused_variables)]
    pub fn set_netstack(&self, on: bool) {
        #[cfg(all(unix, feature = "netstack"))]
        set_netstack_enabled(on);
    }

    /// ★ N-WARDEN (#144) — install the flow-owner UID resolver (Kotlin's
    /// `ConnectivityManager.getConnectionOwnerUid` wrapper). Threaded into the netstack forwarder
    /// at the NEXT `start` so the Warden verdict rules on a REAL uid instead of the permanently
    /// abstaining `-1`. Install BEFORE `start` (alongside the protect callback). Without it — or on
    /// a base (non-netstack) `.so` — the gate fail-safes to pass: the Warden can only ADD a block.
    pub fn set_uid_resolver(&self, resolver: Arc<dyn UidResolver>) {
        *self.uid_resolver.lock().unwrap() = Some(resolver);
    }

    /// ★ N6 (#144) — the forwarder-plane telemetry snapshot (counts only, T20). The CAKE-fountain
    /// card polls this next to [`Self::snapshot`]. On a base (non-netstack) `.so`, or while the
    /// forwarder never ran, every count is 0 and `armed`/`live` are honest `false` — the card
    /// renders DORMANT instead of fabricating motion.
    pub fn forwarder_snapshot(&self) -> ForwarderSnapshot {
        #[cfg(all(unix, feature = "netstack"))]
        let armed = netstack_enabled();
        #[cfg(not(all(unix, feature = "netstack")))]
        let armed = false;
        self.fwd_stats.snapshot_with(armed)
    }

    /// ★ #47 N8 — the PER-FLOW docket: one row per flow live right now, newest last. The aggregate
    /// [`Self::forwarder_snapshot`] answers "how many"; this answers "which ones, and what is the
    /// engine doing to each". Counts and classes only — no address, port or hostname (T20).
    ///
    /// Empty is the honest reading in three distinct situations the panel must not conflate: a base
    /// (non-netstack) `.so`, an armed-but-never-started forwarder, and a live forwarder with no
    /// flows this instant. `forwarder_snapshot().live` is the discriminator between them.
    ///
    /// The list is CAPPED at [`FLOW_DOCKET_CAP`]; compare its length against
    /// `forwarder_snapshot().active_flows` to render "N of M" rather than implying completeness.
    pub fn forwarder_flow_docket(&self) -> Vec<ForwarderFlowRow> {
        docket_rows()
    }
}

impl Default for TunnelController {
    fn default() -> Self {
        Self::build()
    }
}

// ===================================================================================================
// The fd loop — unix-gated (Android/Linux). On non-unix hosts the controller ships without start/stop;
// the pure logic (parse/synth/warden) stays cross-platform + host-testable.
// ===================================================================================================

/// The poll timeout for the read loop: the loop wakes every this-many ms to re-check the stop flag,
/// so [`TunnelController::stop`] is responsive without `O_NONBLOCK` (Q-ground-3, the tun-rs shape).
#[cfg(unix)]
const POLL_TIMEOUT_MILLIS: libc::c_int = 250;

#[cfg(unix)]
impl TunnelController {
    /// **Risk 1 fd-handoff + the loop (unix internals).** `tun_fd` is the raw int Kotlin obtained
    /// from `ParcelFileDescriptor.detachFd()` (Kotlin relinquishes the int; it is NOT closed by
    /// either side — the one-fd-per-start safety). Rust dups it into an [`OwnedFd`] (closing the
    /// DUP on stop), spawns a dedicated OS thread (the listener.rs:152 precedent), and drives the
    /// read→parse→resolve→synth→write loop until [`stop`](Self::stop). Private to this module: the
    /// UniFFI-facing [`Self::start`] (task 1B) is the public surface; it installs the protect
    /// callback, builds the [`TunnelConfig`], and dispatches here.
    ///
    /// Idempotent: a second call while running is a no-op (returns `false`). Returns `true` when
    /// the loop thread was spawned.
    fn start_unix(&self, tun_fd: i32, cfg: TunnelConfig) -> bool {
        // Install the log sink FIRST: every diagnostic below (protected-dial failures and
        // their destinations) is discarded by the `log` facade until this runs.
        crate::devicelog::init_device_logging();
        // A new tunnel is a new network: forget which families the OLD one could reach.
        crate::egress::reset_for_new_network();
        // Idempotency: only spin up the loop if not already running.
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }

        // R1: dup the incoming int. The OwnedFd owns the DUP; the original `tun_fd` int is never
        // closed by Rust (the spec contract — neither side closes the original int).
        // SAFETY: `libc::dup` is a POSIX fd syscall; passing a valid (non-negative) int is the
        // documented contract. A negative return (error) is handled below — no fd is owned on error.
        let dup_fd = unsafe { libc::dup(tun_fd) };
        if dup_fd < 0 {
            self.running.store(false, Ordering::Release);
            return false;
        }
        // SAFETY: `dup_fd` is a freshly-allocated kernel fd we now own exclusively; `from_raw_fd`
        // transfers its ownership to the `OwnedFd` (closed on drop). Nobody else has this int.
        let owned = unsafe {
            <std::os::unix::io::OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(dup_fd)
        };

        let running = self.running.clone();
        let stats = self.stats.clone();

        // ★ NETSTACK GENESIS (#144) — the FORWARDER fork. When the `netstack` feature is compiled AND the
        // runtime toggle is armed (`netstack_enabled()`), spawn the async ipstack forwarder that carries
        // non-DNS traffic OUT of the tun (so DNSCrypt resolves PAGES) while answering `:53` inline via
        // DNSCrypt (DNS preserved). Otherwise the PROVEN sync DNS-only loop runs — byte-identical to today,
        // ZERO DNS risk. The gate is BOTH compile-time (feature) AND runtime (toggle) so a netstack-built
        // `.so` still ships the sync loop until the toggle flips — witness-then-default discipline.
        // `owned` may be moved into the forwarder; `spawn_netstack_forwarder` returns it back (Err) if it
        // declined, so the sync loop still owns the fd on the fall-through.
        #[cfg(all(unix, feature = "netstack"))]
        let owned = if netstack_enabled() {
            // 1E — the protect callback threads into the forwarder's upstream dials; the sync
            // DNS-only loop below never dials out, so the clone lives inside the fork.
            let protect = self.protect.lock().unwrap().clone();
            let uid_resolver = self.uid_resolver.lock().unwrap().clone();
            match spawn_netstack_forwarder(
                cfg.mtu,
                owned,
                protect,
                running.clone(),
                self.fwd_stats.clone(),
                uid_resolver,
            ) {
                Ok(handle) => {
                    *self.join.lock().unwrap() = Some(handle);
                    return true;
                }
                Err(fd) => fd, // forwarder declined — reclaim the fd for the sync loop (fail-safe: DNS lives)
            }
        } else {
            owned
        };

        let handle = std::thread::Builder::new()
            .name("torta-tun-loop".to_string())
            .spawn(move || {
                run_loop(owned, cfg, running, stats);
            })
            .expect("torta-tun-loop spawn");

        *self.join.lock().unwrap() = Some(handle);
        true
    }

    /// Stop the loop (unix internals): signal the stop flag, join the thread (within
    /// `POLL_TIMEOUT_MILLIS` + a read), drop the OwnedFd (closes the dup). The original int
    /// (Kotlin-side) is untouched. Private: the UniFFI-facing [`Self::stop`] dispatches here.
    fn stop_unix(&self) {
        self.running.store(false, Ordering::Release);
        if let Some(handle) = self.join.lock().unwrap().take() {
            let _ = handle.join();
        }
        // The OwnedFd is owned by the loop thread; it drops (closes the dup) when `run_loop`
        // returns. The original `tun_fd` int was never ours to close.
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// ★ NETSTACK GENESIS (#144) — the FORWARDER launch (gated `all(unix, feature = "netstack")`).
// The runtime toggle + the spawn that owns the tun fd on a tokio runtime and drives the ipstack forwarder.
// ════════════════════════════════════════════════════════════════════════════════════════════════════

/// The runtime toggle for the netstack forwarder. OFF by default (`false`) so a `netstack`-built `.so` still
/// runs the PROVEN sync DNS-only loop until the toggle flips — the witness-then-default discipline (never
/// change the default datapath until the forwarder is proven live). Flipped via [`set_netstack_enabled`].
#[cfg(all(unix, feature = "netstack"))]
static NETSTACK_ENABLED: AtomicBool = AtomicBool::new(false);

/// Read the netstack toggle (the sync loop is the default until this is armed).
#[cfg(all(unix, feature = "netstack"))]
fn netstack_enabled() -> bool {
    NETSTACK_ENABLED.load(Ordering::Acquire)
}

/// Arm/disarm the netstack forwarder (the UniFFI front-door `tunnel_set_netstack` calls this). Takes effect
/// on the NEXT `start` — an in-flight loop is not hot-swapped (the VpnService re-establish carries the change).
#[cfg(all(unix, feature = "netstack"))]
pub(crate) fn set_netstack_enabled(on: bool) {
    NETSTACK_ENABLED.store(on, Ordering::Release);
}

/// Spawn the async ipstack forwarder on its OWN tokio current-thread runtime + thread. Consumes `owned`
/// (the tun fd). On success returns the join handle; on failure returns the fd back (`Err`) so the caller
/// falls through to the sync loop — DNS never dies because the forwarder could not spin up.
///
/// A `protect` callback is REQUIRED (the anti-loop keystone): without it every forwarded socket would
/// re-enter the tun. If none is installed we decline (return the fd) — the sync DNS loop is the safe default.
#[cfg(all(unix, feature = "netstack"))]
fn spawn_netstack_forwarder(
    tun_mtu: usize,
    owned: std::os::unix::io::OwnedFd,
    protect: Option<Arc<dyn ProtectCallback>>,
    running: Arc<AtomicBool>,
    fwd: Arc<ForwarderStats>,
    uid_resolver: Option<Arc<dyn UidResolver>>,
) -> Result<std::thread::JoinHandle<()>, std::os::unix::io::OwnedFd> {
    // The forwarder MUST protect its upstream sockets. No callback ⇒ decline (return the fd for the sync loop).
    let Some(cb) = protect else {
        return Err(owned);
    };
    // Adapt the `Arc<dyn ProtectCallback>` into the forwarder's `Fn(i32) -> bool` (`ProtectFn`).
    let protect_fn: crate::forwarder::ProtectFn = Arc::new(move |fd: i32| cb.protect_fd(fd));
    // ★ N-warden — adapt the `Arc<dyn UidResolver>` into the forwarder's `UidFn` (the ProtectFn
    // shape: the forwarder never depends on the UniFFI trait directly). `None` stays `None` — the
    // gate then passes `uid = -1` and the C-ABI ABSTAINs (fail-safe pass).
    let uid_fn: Option<crate::forwarder::UidFn> = uid_resolver.map(|r| {
        Arc::new(
            move |proto: u8, src: std::net::SocketAddr, dst: std::net::SocketAddr| {
                r.uid_of(
                    proto as i32,
                    src.ip().to_string(),
                    src.port(),
                    dst.ip().to_string(),
                    dst.port(),
                )
            },
        ) as crate::forwarder::UidFn
    });

    // Reconstruct-on-failure: keep the raw fd so a (rare) spawn failure can hand a LIVE fd back to the caller
    // for the sync loop. On the success path the OwnedFd moves into the thread (owns + closes it on exit).
    use std::os::unix::io::AsRawFd;
    let raw = owned.as_raw_fd();
    let running_for_err = running.clone(); // the Err branch marks not-running; the closure owns the original
    let spawn = std::thread::Builder::new()
        .name("torta-netstack".to_string())
        .spawn(move || {
            // A current-thread tokio runtime (one worker) — the same shape the resolver uses; the forwarder
            // is I/O-bound (splices), tasks interleave on the one worker. A build/wrap failure just means the
            // loop never runs (the fd drops, closing the dup) — fail-safe, the controller stays up.
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                // Wrap the tun fd async (O_NONBLOCK + reactor register). MUST be inside the runtime context.
                match crate::forwarder::AsyncTunDevice::from_owned(owned) {
                    Ok(device) => {
                        crate::forwarder::run_forwarder(
                            device, protect_fn, running, fwd, uid_fn, tun_mtu,
                        )
                        .await
                    }
                    Err(_) => { /* wrap failed — the fd drops here (closes); the controller stays alive */ }
                }
            });
        });

    match spawn {
        Ok(h) => Ok(h),
        Err(_) => {
            // Thread spawn failed (effectively unreachable on Android under normal load). The OwnedFd moved
            // into the closure and was dropped (closed) when the closure was destroyed. Hand the caller a
            // FRESH dup of the original tun fd so its sync loop has a live fd (the original int is still open
            // Kotlin-side — `raw` was our dup, but the ORIGINAL detached int is what we re-dup here is not
            // available; instead re-dup our raw before it closed is racy). Safest: dup `raw` — if it already
            // closed, dup returns -1 and we signal not-running. SAFETY: `raw` was a valid fd int.
            let re = unsafe { libc::dup(raw) };
            if re >= 0 {
                Err(unsafe {
                    <std::os::unix::io::OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(re)
                })
            } else {
                // The fd already closed with the dropped closure — we cannot revive it. Mark not-running so
                // the controller reports failure; the VpnService re-establish will retry a clean start.
                running_for_err.store(false, Ordering::Release);
                let devnull = unsafe {
                    libc::open(
                        // A c"..." literal is NUL-terminated by the compiler, so the terminator cannot
                    // be dropped by an edit the way a hand-written \0 inside a byte string can --
                    // and losing it here would hand libc::open a pointer with no end, which reads
                    // past the literal.
                    c"/dev/null".as_ptr(),
                        libc::O_RDONLY,
                    )
                };
                Err(unsafe {
                    <std::os::unix::io::OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(
                        devnull.max(0),
                    )
                })
            }
        }
    }
}

/// The read→parse→resolve→synth→write loop. Runs on a dedicated OS thread (the listener.rs:152
/// precedent); checks `running` every `POLL_TIMEOUT_MILLIS` so stop is responsive.
#[cfg(unix)]
fn run_loop(
    owned: std::os::unix::io::OwnedFd,
    cfg: TunnelConfig,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
) {
    use std::os::unix::io::AsRawFd;

    let fd = owned.as_raw_fd();
    let mut buf = vec![0u8; cfg.mtu.max(64)];

    while running.load(Ordering::Acquire) {
        // Poll with a bounded timeout so the stop flag is re-checked promptly (Q-ground-3). A
        // straight blocking `read` would not wake on stop; `poll` decouples liveness from stop.
        // SAFETY: `pollfd` is stack-local; `fd` is the live OwnedFd's raw int (valid for the call).
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the pollfd points at our stack-local struct; the fd is valid for the duration.
        let pr = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, POLL_TIMEOUT_MILLIS) };
        if pr < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue; // a signal interrupted poll — re-check the stop flag + retry
            }
            stats.io_errors.fetch_add(1, Ordering::Relaxed);
            continue; // a transient poll error: count + swallow, never tear the loop
        }
        if pr == 0 {
            continue; // timeout — re-check the stop flag
        }
        if (pfd.revents & libc::POLLIN) == 0 {
            // An error/hangup on the fd: read will return the error; fall through to read so the
            // loop sees the EOF/error and reports it (rather than spinning on revents alone).
            if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                stats.io_errors.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }

        // SAFETY: `fd` is the live OwnedFd's raw int; `buf` owns `cfg.mtu` bytes; read at most that.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            stats.io_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if n == 0 {
            // EOF on the tun — the VpnService tore it down. Exit the loop (the controller will be
            // re-established on the next VPN up).
            break;
        }
        let n = n as usize;
        stats.pkts_in.fetch_add(1, Ordering::Relaxed);
        let frame = handle_packet(&buf[..n], &cfg, &stats);
        if let Some(reply) = frame {
            // SAFETY: `fd` is the live OwnedFd's raw int; `reply` is a fully-owned Vec; the write
            // consumes exactly `reply.len()` bytes from the slice.
            let mut written = 0usize;
            while written < reply.len() {
                let w = unsafe {
                    libc::write(
                        fd,
                        reply[written..].as_ptr() as *const libc::c_void,
                        reply.len() - written,
                    )
                };
                if w < 0 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if e == libc::EINTR {
                        continue;
                    }
                    stats.io_errors.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                written += w as usize;
            }
        }
    }
    // OwnedFd drops here → closes the dup (R1). The original int (Kotlin-side) is untouched.
}

// ===================================================================================================
// handle_packet — the dispatch: parse → (DNS intercept | Warden gate). Pure logic, host-testable.
// ===================================================================================================

/// Decide what to do with one parsed packet. Returns the reply frame to write back, or `None` to
/// drop (a non-DNS packet the Warden allowed — Stage-2-min does not forward TCP/ICMP; or a Warden
/// DENY; or a parse failure). This is the cross-platform core the loop thread calls.
fn handle_packet(pkt: &[u8], cfg: &TunnelConfig, stats: &TunnelStats) -> Option<Vec<u8>> {
    let parsed = match parse::parse_ip_udp(pkt) {
        Some(p) => p,
        None => {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
    };

    // The DNS-intercept path: UDP + dport==53 + fwd53. The `!fwd53` short-circuit (udp.c:213-214)
    // drops the intercept (the loop does NOT answer :53 when fwd53 is off).
    let is_dns = parsed.is_dns_query() && cfg.fwd53;
    if !is_dns {
        // Non-DNS or !fwd53: apply the Warden gate (Stage-2-min forward_or_warden_drop). DENY ⇒ drop;
        // ALLOW/ABSTAIN ⇒ also drop (Stage-2-min does not forward TCP/ICMP — that's Stage-3 work).
        // The Warden is consulted for telemetry + future forwarding; the answer is "drop" either way
        // until Stage-3 adds the TCP/UDP forward state machine (deliberately DROPPED per spec §3).
        // #20 ROW HONESTY: the real dport (UDP or TCP — never a fabricated 0 for TCP), and
        // `carries: false` — this loop drops every flow it judges here, and the panel row must say
        // so (DROPPED, not a false ALLOW).
        let _ = warden::verdict(
            -1, // UID unresolved at the Rust layer in Stage-2-min (the C engine's uid lookup is dropped)
            parsed.version,
            parsed.proto,
            &parsed.dst_ip,
            parsed
                .udp
                .as_ref()
                .map(|u| u.dport)
                .or(parsed.tcp_dport)
                .unwrap_or(0),
            None,
            false,
        );
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let udp = parsed.udp.unwrap();
    stats.dns_intercepted.fetch_add(1, Ordering::Relaxed);

    // Edge #15-16: a DNS payload shorter than the header, or not a standard query, ⇒ drop (the
    // resolver handles it; the loop only intercepts qr==0 standard queries — udp.c:412 gate).
    if udp.payload.len() < parse::DNS_HEADER_LEN || !is_standard_query(udp.payload) {
        stats.dropped.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    // Edge #21: bypass_lan — the 13-suffix LAN/mDNS list (udp.c:449-466). A qname matching a LAN
    // suffix is NOT intercepted (left to the system resolver); drop the intercept.
    if cfg.bypass_lan {
        if let Some((qname, _)) = parse::extract_qname(udp.payload) {
            if parse::matches_lan_suffix(&qname) {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }

    // The Warden gate ON THE DNS PATH — the path `cfg.blocked_rcode` was written for and which did
    // not exist.
    //
    // Measured, not assumed: `blocked_rcode` is accepted over the FFI (`start`, clamped 0..=255 at
    // :620), stored on `TunnelConfig`, documented as "the DNS rcode to stamp on a Warden-DENY'd DNS
    // query" — and was read by NOTHING. An operator could set it to any value and the engine's
    // behaviour was byte-identical, because DNS queries reached the resolver without the Warden
    // ever being consulted. The non-DNS branch above consults the Warden; this branch did not.
    //
    // Consulted by QNAME, with `uid = -1`: the C engine's uid lookup is dropped at Stage-2-min, so
    // a per-app decision is not available here and a domain rule is the honest scope. The Warden
    // ABSTAINS when its facts are insufficient, so an unconfigured Warden changes nothing.
    //
    // DENY answers with the OPERATOR's rcode rather than dropping. A drop makes the stub retry
    // until it times out ("DNS dead"); an answer is immediate and honest about the refusal. This is
    // the same reasoning the transport-miss site records, applied in the opposite direction: THIS
    // is a name we DECIDED to deny, so operator policy is exactly what belongs here — whereas a
    // transport miss must never borrow it (see `transport_miss_never_borrows_the_block_rcode`).
    // T20 — the consultation is READ-ONLY and records NOTHING unless it actually denies.
    //
    // The first cut called `warden::verdict(...)` for every DNS query. That was wrong twice over,
    // and the second reason is the serious one:
    //  1. It broke `canonical_attribution_only_deny_still_dies_on_the_bare_re_ask` (ring rows 2 vs
    //     1) -- the visible symptom.
    //  2. `verdict` RECORDS a judgment row carrying the qname. Consulting it per query would have
    //     turned the Warden tracker ring into a BROWSING HISTORY: every domain the device resolved,
    //     retained on disk, for no policy gain -- since an unarmed Warden abstains on all of them.
    //     That is exactly the per-domain log this codebase refuses to keep.
    //
    // So the gate uses the same read-only `rule_sets().domain.matches(...)` the dry-run rule probe
    // uses (`lib.rs:1328` -- REUSE, not a second matcher), and only the DENIES -- which are genuine
    // policy events an operator asked to happen -- go on to be recorded by `verdict`.
    if let Some((qname, _)) = parse::extract_qname(udp.payload) {
        let denied = !qname.is_empty()
            && match crate::warden_lock().as_ref() {
                Some(w) => w.rule_sets().domain.matches(crate::warden::UID_UNIVERSAL, &qname),
                None => false,
            };
        if denied {
            // NOW record it: a policy refusal is worth a row, and there is one row per refusal
            // rather than one per query.
            let _ = warden::verdict(
                -1,
                parsed.version,
                parsed.proto,
                &parsed.dst_ip,
                udp.dport,
                Some(&qname),
                false,
            );
            stats.dns_warden_denied.fetch_add(1, Ordering::Relaxed);
            let reply = synth::synthesize_servfail(udp.payload, cfg.blocked_rcode);
            return Some(synth::synth_ip_udp_reply(&parsed, &reply));
        }
    }

    // The resolve. We ride `resolve_datapath` — the LIVE datapath seam `torta_resolve` (lib.rs:1987)
    // calls — identical to `resolve` until a review surface is armed, then the wall clock + the
    // verdict feed fire here too. No `dlsym`, no cross-library flag: a direct in-crate call.
    let reply_dns = crate::resolver::resolve_datapath(udp.payload);

    let reply_dns = match reply_dns {
        Some(r) => {
            stats.dns_answered.fetch_add(1, Ordering::Relaxed);
            // A4 — remember `answer IP → query qname` while the reply is in our hands: a later
            // flow to that IP carries the domain the app actually asked for. Best-effort by law
            // (attribution.rs) — a malformed/empty reply records nothing, never errors.
            let _ = crate::warden::attribution::record_from_reply(&r);
            r
        }
        None => {
            // R4 — no-Go-fallback. With the Go binary gone, a resolver None is NO LONGER a
            // fall-through to a working upstream. Synthesize SERVFAIL around the original query and
            // write it back — NEVER silently drop (the stub retries forever, "DNS dead").
            stats.dns_servfail.fetch_add(1, Ordering::Relaxed);
            // A transport miss is NOT a policy block, and must never borrow the block rcode.
            // `blocked_rcode` is operator policy for names we DECIDED to deny; when it is set to
            // NXDOMAIN the stub and the app both negatively cache the name, so a single timeout or
            // pool exhaustion turns into "this domain does not exist" — permanently, at 0ms, for
            // every app that asked. SERVFAIL is the only honest answer here: it says "I failed",
            // not "it isn't there", and clients retry instead of caching the lie.
            synth::synthesize_servfail(udp.payload, RCODE_SERVFAIL)
        }
    };

    // The write_udp twin: swap src↔dst, valid IP+UDP checksums, full frame for `write(tun_fd, _)`.
    Some(synth::synth_ip_udp_reply(&parsed, &reply_dns))
}

/// Is `dns_payload` a standard query (qr==0, opcode==0, qdcount>0)? The udp.c:412 gate.
fn is_standard_query(dns_payload: &[u8]) -> bool {
    if dns_payload.len() < parse::DNS_HEADER_LEN {
        return false;
    }
    let byte2 = dns_payload[2];
    let qr = (byte2 >> 7) & 0x01;
    let opcode = (byte2 >> 3) & 0x0F;
    let qdcount = u16::from_be_bytes([dns_payload[4], dns_payload[5]]);
    qr == 0 && opcode == 0 && qdcount > 0
}

// ===================================================================================================
// Tests — the dispatch logic, host-runnable (no fd, no resolver needed for the parse/synth paths).
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_v4_udp_dns(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        dns: &[u8],
    ) -> Vec<u8> {
        let total = parse::IP4_HEADER_LEN + parse::UDP_HEADER_LEN + dns.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = parse::IPPROTO_UDP;
        p[12..16].copy_from_slice(&src_ip);
        p[16..20].copy_from_slice(&dst_ip);
        let u = parse::IP4_HEADER_LEN;
        p[u..u + 2].copy_from_slice(&sport.to_be_bytes());
        p[u + 2..u + 4].copy_from_slice(&dport.to_be_bytes());
        let ulen = (parse::UDP_HEADER_LEN + dns.len()) as u16;
        p[u + 4..u + 6].copy_from_slice(&ulen.to_be_bytes());
        p[u + parse::UDP_HEADER_LEN..].copy_from_slice(dns);
        p
    }

    fn example_dns_query() -> Vec<u8> {
        let mut d = vec![0u8; parse::DNS_HEADER_LEN];
        d[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        d[4..6].copy_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(b"\x07example\x03com\x00");
        d.extend_from_slice(&1u16.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes());
        d
    }

    #[test]
    fn standard_query_classifier() {
        let q = example_dns_query();
        assert!(is_standard_query(&q));
        // A response (qr=1) is NOT a standard query.
        let mut r = q.clone();
        r[2] |= 0x80;
        assert!(!is_standard_query(&r));
    }

    #[test]
    fn handle_packet_drops_malformed_ip() {
        let stats = TunnelStats::default();
        let cfg = TunnelConfig::default();
        // Garbage bytes — not a valid IP packet.
        assert!(handle_packet(&[0x55u8; 40], &cfg, &stats).is_none());
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_packet_servfails_when_resolver_unconfigured() {
        // The resolver is unconfigured in the bare test env ⇒ resolve_datapath returns None ⇒ the
        // loop synthesizes SERVFAIL (Risk 4) and writes it back. This is the no-Go-fallback proof.
        // ★ #100 — "unconfigured" is a PROCESS-GLOBAL claim, so it must be established under the
        // shared gate: sibling tests install a pool and never tear it down. Without this the test
        // passes or fails depending on thread scheduling (measured: same command, 2 failed then 0).
        let _serial = crate::resolver::lock_global_unconfigured();
        let stats = TunnelStats::default();
        let cfg = TunnelConfig::default();
        let dns = example_dns_query();
        let pkt = build_v4_udp_dns([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &dns);
        let reply = handle_packet(&pkt, &cfg, &stats).expect("a SERVFAIL reply frame");
        // The reply frame is IP+UDP+SERVFAIL. The DNS body is at the UDP payload offset.
        let body_off = parse::IP4_HEADER_LEN + parse::UDP_HEADER_LEN;
        let body = &reply[body_off..];
        assert_eq!(body[0..2], dns[0..2], "ID echoed");
        assert_eq!(body[2] & 0x80, 0x80, "QR set");
        assert_eq!(body[3] & 0x0F, RCODE_SERVFAIL, "rcode = SERVFAIL");
        assert_eq!(stats.dns_servfail.load(Ordering::Relaxed), 1);
        assert_eq!(stats.dns_intercepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_packet_short_circuits_when_fwd53_off() {
        // The udp.c:213-214 !fwd53 edge: when fwd53 is false, the loop does NOT intercept :53.
        let stats = TunnelStats::default();
        let cfg = TunnelConfig {
            fwd53: false,
            ..TunnelConfig::default()
        };
        let dns = example_dns_query();
        let pkt = build_v4_udp_dns([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &dns);
        // fwd53 off ⇒ not a DNS intercept ⇒ the Warden-gate path ⇒ drop.
        assert!(handle_packet(&pkt, &cfg, &stats).is_none());
        assert_eq!(stats.dns_intercepted.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_packet_skips_lan_suffix_when_bypass_lan() {
        // The udp.c:449-466 bypass_lan list: a .local qname is NOT intercepted.
        let stats = TunnelStats::default();
        let cfg = TunnelConfig::default(); // bypass_lan = true
        let mut dns = vec![0u8; parse::DNS_HEADER_LEN];
        dns[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount = 1
        dns.extend_from_slice(b"\x06myhost\x05local\x00");
        dns.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        dns.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        let pkt = build_v4_udp_dns([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &dns);
        assert!(handle_packet(&pkt, &cfg, &stats).is_none());
        assert_eq!(stats.dns_intercepted.load(Ordering::Relaxed), 1);
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 1); // the LAN-suffix skip counts as a drop
    }

    #[test]
    fn controller_constructs_idle() {
        let c = TunnelController::new();
        assert!(!c.is_running());
        let snap = c.snapshot();
        assert!(!snap.running);
        assert_eq!(snap.pkts_in, 0);
    }

    /// A no-op ProtectCallback for the trait surface (1E wires the real Kotlin impl).
    struct NoopProtect;
    impl ProtectCallback for NoopProtect {
        fn protect_fd(&self, _fd: i32) -> bool {
            true
        }
    }

    #[test]
    fn protect_callback_installs_and_retrieves() {
        let c = TunnelController::new();
        c.set_protect_callback(Arc::new(NoopProtect));
        assert!(c.protect_callback().is_some());
    }

    // ★ N6 (#144) — the forwarder telemetry surface.

    #[test]
    fn forwarder_snapshot_is_all_zero_and_disarmed_at_birth() {
        // A fresh controller (no forwarder ever ran) reads an HONEST dormant snapshot: every count
        // zero, `armed`/`live` false — the CAKE-fountain card must render DORMANT, never fabricate.
        let c = TunnelController::new();
        let snap = c.forwarder_snapshot();
        assert_eq!(snap, ForwarderSnapshot::default());
        assert!(!snap.armed);
        assert!(!snap.live);
        assert_eq!(snap.flows_tcp + snap.flows_udp + snap.flows_other, 0);
        assert_eq!(snap.cwnd_last, 0);
    }

    /// ★ #47 N8 — serializes the docket tests against each other, self-enforcing the discipline the
    /// external `--test-threads=1` flag only *asks* for. MEASURED, not assumed: the first draft of
    /// these tests trusted a sibling module's "the crate runs --test-threads=1" comment and flaked
    /// immediately under the default parallel harness (a non-empty docket at the start of the
    /// round-trip test, and 255-of-256 rows in the cap test — a sibling drained the global between
    /// another test's fill and its assert). Same idiom + same reason as `underground::tests::SERIAL`
    /// and `lock_warden_global`. Poison-tolerant so one panicking test cannot cascade-fail the rest.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Take the serial gate and start from a drained docket. Bind the return
    /// (`let _serial = docket_scrub();`) — the `must_use` makes a bare `docket_scrub();`, which would
    /// drop the guard inline and silently un-serialize the test, a compile warning.
    #[must_use = "hold the guard for the whole test body: `let _serial = docket_scrub();`"]
    fn docket_scrub() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(mut d) = FLOW_DOCKET.lock() {
            d.clear();
        }
        g
    }

    #[test]
    fn flow_docket_round_trips_one_live_flow_field_for_field() {
        let _serial = docket_scrub();
        // Empty at birth — a controller whose forwarder never ran lists NO flows (the honest
        // dormant reading, same law as the all-zero aggregate snapshot above).
        let c = TunnelController::new();
        assert!(c.forwarder_flow_docket().is_empty());

        // Enroll ONE flow and give every field a DISTINCT value, so a crossed-wire mapping in
        // `FlowLive::row()` cannot pass this test.
        let live = Arc::new(FlowLive::new(0x5A5A_1234, 6, 1, true));
        assert!(docket_register(&live));
        live.cwnd.store(7, Ordering::Relaxed);
        live.bytes_up.store(1111, Ordering::Relaxed);
        live.bytes_down.store(2222, Ordering::Relaxed);
        live.rtt_ms.store(33, Ordering::Relaxed);
        live.stalls.store(4, Ordering::Relaxed);

        let rows = c.forwarder_flow_docket();
        assert_eq!(rows.len(), 1, "the live flow never reached the docket");
        let r = rows[0];
        assert_eq!(r.key, 0x5A5A_1234);
        assert_eq!(r.proto, 6, "TCP must cross as the IANA number, not a flag");
        assert_eq!(r.tin, 1);
        assert!(r.paced);
        assert_eq!(r.cwnd, 7);
        assert_eq!(r.bytes_up, 1111);
        assert_eq!(r.bytes_down, 2222);
        assert_eq!(r.rtt_ms, 33);
        assert_eq!(r.stalls, 4);

        // The flow ends → its row leaves the docket. A docket that kept dead flows would report
        // phantom traffic forever.
        docket_release(&live);
        assert!(c.forwarder_flow_docket().is_empty());
    }

    #[test]
    fn a_fresh_row_reports_rtt_unmeasured_not_zero() {
        let _serial = docket_scrub();
        // THE EMPTY-STATE LAW (the #96 beast fix, applied at birth): an unmeasured RTT must be
        // distinguishable from a measured 0 ms, or the panel renders a fabricated instant flow.
        let live = Arc::new(FlowLive::new(1, 17, 2, false));
        assert_eq!(live.row().rtt_ms, -1);
        // An unpaced flow honestly carries NO window rather than "window 0".
        assert_eq!(live.row().cwnd, 0);
        assert!(!live.row().paced);
    }

    #[test]
    fn docket_refuses_past_cap_and_never_blocks_the_flow() {
        let _serial = docket_scrub();
        // Fill to capacity, keeping the Arcs alive so the rows stay enrolled.
        let held: Vec<_> = (0..FLOW_DOCKET_CAP)
            .map(|i| {
                let row = Arc::new(FlowLive::new(i as i64, 6, 2, false));
                assert!(docket_register(&row), "row {i} refused below the cap");
                row
            })
            .collect();
        assert_eq!(docket_rows().len(), FLOW_DOCKET_CAP);

        // The next flow is REFUSED a docket slot — and that is a reporting gap, not an outage: the
        // caller forwards it regardless, which is why `docket_register` returns a bool the datapath
        // is free to ignore rather than an error it must handle.
        let overflow = Arc::new(FlowLive::new(-1, 6, 2, false));
        assert!(!docket_register(&overflow));
        assert_eq!(docket_rows().len(), FLOW_DOCKET_CAP, "cap was exceeded");

        // Releasing a row frees the slot for the next flow.
        docket_release(&held[0]);
        assert!(docket_register(&overflow));
        // No trailing drain: every docket test scrubs on ENTRY while holding the serial gate, so
        // residue cannot reach a sibling. (A second `docket_scrub()` here would re-lock a
        // non-reentrant Mutex on the same thread — a self-deadlock, not a cleanup.)
    }

    #[test]
    fn release_retires_by_identity_not_by_colliding_key() {
        let _serial = docket_scrub();
        // Two live flows CAN fold to the same CAKE key (it is a hash). Releasing one must retire
        // exactly that row — a key-matching release would retire the wrong flow's row and leave a
        // dead flow listed forever.
        let a = Arc::new(FlowLive::new(777, 6, 2, true));
        let b = Arc::new(FlowLive::new(777, 17, 0, false));
        assert!(docket_register(&a));
        assert!(docket_register(&b));
        assert_eq!(docket_rows().len(), 2);

        docket_release(&a);
        let rows = docket_rows();
        assert_eq!(rows.len(), 1, "release retired more than its own row");
        // The SURVIVOR is b — proven by a field the two differ on, not by the shared key.
        assert_eq!(rows[0].proto, 17, "release retired the wrong row");
        assert_eq!(rows[0].tin, 0);
    }

    #[test]
    fn forwarder_stats_snapshot_reads_every_counter() {
        // Every ForwarderStats field must land in its ForwarderSnapshot twin (distinct values so a
        // crossed-wire field mapping cannot pass), and `armed` passes through from the caller.
        let s = ForwarderStats::default();
        s.live.store(true, Ordering::Relaxed);
        s.flows_tcp.store(1, Ordering::Relaxed);
        s.flows_udp.store(2, Ordering::Relaxed);
        s.flows_other.store(3, Ordering::Relaxed);
        s.active_flows.store(4, Ordering::Relaxed);
        s.tin_critical.store(5, Ordering::Relaxed);
        s.tin_high.store(6, Ordering::Relaxed);
        s.tin_normal.store(7, Ordering::Relaxed);
        s.dns_answered.store(8, Ordering::Relaxed);
        s.paced_flows.store(9, Ordering::Relaxed);
        s.bytes_up.store(10, Ordering::Relaxed);
        s.bytes_down.store(11, Ordering::Relaxed);
        s.rtt_samples.store(12, Ordering::Relaxed);
        s.stalls.store(13, Ordering::Relaxed);
        s.cwnd_last.store(14, Ordering::Relaxed);
        s.warden_denied.store(15, Ordering::Relaxed);
        // ★ #51 — the echo lane's three counters ride the same coherent read.
        s.icmp_echo.store(16, Ordering::Relaxed);
        s.icmp_replied.store(17, Ordering::Relaxed);
        s.icmp_failed.store(18, Ordering::Relaxed);
        let snap = s.snapshot_with(true);
        assert!(snap.armed && snap.live);
        assert_eq!(
            (snap.flows_tcp, snap.flows_udp, snap.flows_other, snap.active_flows),
            (1, 2, 3, 4)
        );
        assert_eq!((snap.tin_critical, snap.tin_high, snap.tin_normal), (5, 6, 7));
        assert_eq!((snap.dns_answered, snap.paced_flows), (8, 9));
        assert_eq!((snap.bytes_up, snap.bytes_down), (10, 11));
        assert_eq!((snap.rtt_samples, snap.stalls, snap.cwnd_last), (12, 13, 14));
        assert_eq!(snap.warden_denied, 15);
        assert_eq!(
            (snap.icmp_echo, snap.icmp_replied, snap.icmp_failed),
            (16, 17, 18),
            "★ #51 — an echo-lane counter is crossed or unread"
        );
        // And the disarmed read keeps the counters while dropping only the toggle.
        assert!(!s.snapshot_with(false).armed);
    }

    /// STRUCTURAL LAW — a transport miss must never borrow the operator's BLOCK rcode.
    ///
    /// `blocked_rcode` is policy for names we DECIDED to deny, and it is caller-supplied over the
    /// FFI. When an operator sets it to NXDOMAIN, stamping it onto a resolver `None` tells every
    /// app "this domain does not exist" — which stubs and apps negatively cache, so one timeout or
    /// one exhausted pool kills that name persistently, answered in 0 ms with no egress. That was
    /// a real field defect: instant failed queries and dead links on some apps but not others,
    /// depending purely on which names each one resolved.
    ///
    /// `synth::synthesize_servfail`'s own contract already mandates the right value ("pass
    /// RCODE_SERVFAIL (2) for a resolver None"); the call site simply disobeyed it. This test
    /// guards the call site rather than the synth layer, because the synth layer was never wrong.
    /// Structural (source-text) rather than behavioural: driving the datapath needs a live tun fd,
    /// and the regression risk here is textual — someone reaching for `cfg.blocked_rcode` again
    /// because it is in scope and reads plausibly.
    #[test]
    fn transport_miss_never_borrows_the_block_rcode() {
        // Both needles are ASSEMBLED, never written as contiguous literals. `include_str!` reads
        // THIS file, so a literal needle would match its own assertion — the positive check would
        // pass even with the call site deleted, and the negative check could never pass at all.
        // (Found the hard way: the first cut of this test failed against itself.)
        // SPEC CORRECTION. This check used to forbid the needle `synthesize_servfail(udp.payload,
        // cfg.blocked_rcode)` ANYWHERE in this file. That was a snapshot of the code as it stood,
        // not a statement of the law it meant to enforce, and it made a CORRECT change fail: when
        // the Warden DNS gate was wired, the deny path used exactly that call — which is the one
        // thing `blocked_rcode` exists for — and this test went red on code that was entirely
        // right. The obvious repair (delete the assertion) would have destroyed real coverage.
        //
        // The law is scoped to ONE call site: the resolver-None branch must not borrow the block
        // rcode. So the negative check is now scoped to that branch instead of to the whole file,
        // and the file is free to use `cfg.blocked_rcode` where it belongs.
        let src = include_str!("mod.rs");
        let call = format!("synth::{}(udp.payload, ", "synthesize_servfail");
        let good = format!("{call}RCODE_{}", "SERVFAIL)");
        let bad = format!("{call}cfg.{}", "blocked_rcode)");

        // Isolate the transport-miss branch by its own marker comment, then assert INSIDE it.
        let marker = format!("R4 — no-Go-{}", "fallback");
        let start = src
            .find(&marker)
            .expect("the resolver-None branch must still be identifiable by its R4 marker");
        // The window runs FORWARD from the marker only, so it can never accidentally swallow the
        // Warden deny path's legitimate call, which sits earlier in the function. 2000 chars
        // measured: the marker is followed by ~14 lines of rationale before the call itself, and a
        // 900-char window fell short of it.
        let branch = &src[start..(start + 2000).min(src.len())];

        // NON-VACUITY FIRST. If the window does not contain the call being judged, every assertion
        // below is about the wrong region of the file -- and the NEGATIVE one would pass trivially.
        // Checked before the others so a drifted marker reports THAT, rather than masquerading as
        // a missing SERVFAIL stamp (which is exactly how this first failed).
        assert!(
            branch.contains(&call),
            "the extracted window must CONTAIN the synthesize_servfail call, or this test is \
             asserting things about the wrong region of the file"
        );
        assert!(
            branch.contains(&good),
            "the resolver-None branch must stamp RCODE_SERVFAIL (2)"
        );
        assert!(
            !branch.contains(&bad),
            "a transport miss is not a policy block — it must not reuse the block rcode"
        );

        // The legitimate use is REQUIRED to exist: the Warden deny path must stamp the operator's
        // rcode. This is the half the old file-wide ban actively prevented, and stating it turns a
        // prohibition into a two-sided law — the block rcode belongs HERE and nowhere else.
        assert!(
            src.contains(&bad),
            "the Warden DNS deny path must stamp cfg.blocked_rcode — an operator's block policy \
             has to reach the wire somewhere, or the knob is dead again"
        );
    }
}

/// The block-rcode sanitizer — the Rust half of `D:\Lean\proofs\Proofs\BlockedRcode.lean`.
///
/// The proof settles every `i32`; these keep the Rust honest against that model and pin the
/// specific boundary that was a live fail-open.
#[cfg(test)]
mod blocked_rcode_tests {
    use super::*;

    /// THE regression. `blocked_rcode = 16` used to reach the wire as rcode 0 = NOERROR: the
    /// clamp admitted 0..=255 and `apply_servfail_header`'s `& 0x0F` folded 16 onto 0. An operator
    /// asking for a stricter block got a reply that says the lookup SUCCEEDED.
    ///
    /// Lean: `the_fail_open_boundary_is_closed`.
    #[test]
    fn sixteen_no_longer_folds_onto_noerror() {
        assert_eq!(
            sanitize_blocked_rcode(16),
            RCODE_SERVFAIL,
            "16 must NOT fold onto 0 (NOERROR) — that was the fail-open"
        );
        // And prove it at the WIRE, not just at the sanitizer: the stamped header must not be 0.
        let query = crate::dns::build_query(0x1234, "example.com", 1);
        let reply = synth::synthesize_servfail(&query, sanitize_blocked_rcode(16));
        assert_ne!(
            reply[3] & 0x0F,
            0,
            "a BLOCK must never reach the wire as NOERROR"
        );
    }

    /// No input of any kind produces NOERROR. Lean: `never_answers_noerror` settles all of `i32`;
    /// this sweeps the region where the old implementation actually misbehaved.
    #[test]
    fn no_input_can_ever_produce_noerror() {
        for r in -300i32..=300 {
            assert_ne!(
                sanitize_blocked_rcode(r),
                0,
                "input {r} produced NOERROR — a block reported as success"
            );
        }
        // The i32 extremes, where an unchecked cast is most dangerous.
        for r in [i32::MIN, i32::MIN + 1, i32::MAX - 1, i32::MAX] {
            assert_ne!(sanitize_blocked_rcode(r), 0);
        }
    }

    /// Everything the sanitizer emits survives the 4-bit wire stamp unchanged, so the two ends can
    /// no longer disagree about the field's width. Lean:
    /// `stamping_never_alters_a_sanitized_rcode`.
    #[test]
    fn the_four_bit_stamp_never_alters_a_sanitized_value() {
        for r in -300i32..=300 {
            let s = sanitize_blocked_rcode(r);
            assert_eq!(s & 0x0F, s, "input {r} sanitized to {s}, which the wire stamp would alter");
        }
    }

    /// NON-VACUITY: an operator's legal choice is preserved EXACTLY. Without this the sanitizer
    /// could return SERVFAIL for everything and all three tests above would still pass.
    /// Lean: `preserves_every_legal_choice`.
    #[test]
    fn every_legal_operator_choice_is_preserved_exactly() {
        for r in 1i32..=15 {
            assert_eq!(
                sanitize_blocked_rcode(r),
                r as u8,
                "the operator asked for rcode {r} and must GET rcode {r}"
            );
        }
        // And the range genuinely includes values other than the fallback, or "preserved" would be
        // indistinguishable from "always SERVFAIL".
        assert_ne!(sanitize_blocked_rcode(3), RCODE_SERVFAIL, "NXDOMAIN must survive as NXDOMAIN");
    }
}

/// The dial-failure partition, at the Rust boundary. The universal property (total + disjoint, so
/// the four buckets always sum to the total) is PROVED in D:/Lean/proofs/Proofs/DialFailure.lean;
/// these tests pin the model to the real errno constants and to the enum the forwarder matches on.
#[cfg(test)]
mod dial_failure_tests {
    use super::*;

    #[test]
    fn the_named_errnos_map_exactly() {
        assert_eq!(classify_dial_failure(Some(111)), DialFailure::Refused);
        assert_eq!(classify_dial_failure(Some(101)), DialFailure::Unreachable);
        assert_eq!(classify_dial_failure(Some(113)), DialFailure::Unreachable);
        assert_eq!(classify_dial_failure(Some(97)), DialFailure::Unreachable);
        assert_eq!(classify_dial_failure(Some(110)), DialFailure::TimedOut);
    }

    /// The case the old `Err(_)` silently dropped: a failure with no OS error behind it is STILL
    /// counted. This is the whole reason the partition has an explicit catch-all.
    #[test]
    fn a_failure_with_no_errno_is_still_counted() {
        assert_eq!(classify_dial_failure(None), DialFailure::Other);
    }

    /// ★ N-dial-UDP — the WIDENED invariant, on the real `ForwarderStats`.
    ///
    /// The four cause buckets are SHARED by both transports while the two totals stay separate, so
    /// the sum of the buckets must equal `dial_connect_failed + udp_dial_connect_failed` — never
    /// either total alone. Both wrong readings are asserted against explicitly, because the narrow
    /// one (buckets == the TCP total) held for as long as the UDP dial failed in silence and would
    /// therefore have looked correct for the entire life of the bug.
    #[test]
    fn the_shared_buckets_sum_to_both_totals_not_either_alone() {
        let fwd = ForwarderStats::default();
        // Two TCP failures: one refused, one unreachable.
        for errno in [Some(111), Some(101)] {
            fwd.dial_connect_failed.fetch_add(1, Ordering::Relaxed);
            match classify_dial_failure(errno) {
                DialFailure::Refused => &fwd.dial_refused,
                DialFailure::Unreachable => &fwd.dial_unreachable,
                DialFailure::TimedOut => &fwd.dial_timed_out,
                DialFailure::Other => &fwd.dial_other,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
        // Two UDP failures: one timed out, one with no errno at all (the catch-all).
        for errno in [Some(110), None] {
            fwd.udp_dial_connect_failed.fetch_add(1, Ordering::Relaxed);
            match classify_dial_failure(errno) {
                DialFailure::Refused => &fwd.dial_refused,
                DialFailure::Unreachable => &fwd.dial_unreachable,
                DialFailure::TimedOut => &fwd.dial_timed_out,
                DialFailure::Other => &fwd.dial_other,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
        let s = fwd.snapshot_with(true);
        let buckets = s.dial_refused + s.dial_unreachable + s.dial_timed_out + s.dial_other;
        assert_eq!(
            buckets,
            s.dial_connect_failed + s.udp_dial_connect_failed,
            "the shared buckets must partition BOTH totals (Proofs/DialFailure.lean, \
             buckets_sum_to_both_totals)"
        );
        assert_ne!(
            buckets, s.dial_connect_failed,
            "the NARROW invariant must be false once UDP fails — it held only while the UDP dial \
             was silent, which is exactly the bug"
        );
        assert_ne!(
            buckets, s.udp_dial_connect_failed,
            "and neither transport's total may be mistaken for the whole"
        );
        // All four buckets carry weight here, so dropping any one of them breaks this test.
        assert_eq!((s.dial_refused, s.dial_unreachable), (1, 1));
        assert_eq!((s.dial_timed_out, s.dial_other), (1, 1));
    }

    /// `protect()` refusal is counted SEPARATELY per transport and never enters the cause buckets:
    /// it is the VpnService seam, not a network cause, and conflating the two sends the operator
    /// hunting a routing problem that does not exist.
    #[test]
    fn udp_protect_refusal_is_its_own_counter_and_not_a_cause_bucket() {
        let fwd = ForwarderStats::default();
        fwd.udp_dial_protect_failed.fetch_add(1, Ordering::Relaxed);
        let s = fwd.snapshot_with(true);
        assert_eq!(s.udp_dial_protect_failed, 1);
        assert_eq!(s.udp_dial_connect_failed, 0, "a protect refusal never reached the network");
        assert_eq!(
            s.dial_refused + s.dial_unreachable + s.dial_timed_out + s.dial_other,
            0,
            "a protect refusal is not a network cause and must not land in the buckets"
        );
        assert_eq!(s.dial_protect_failed, 0, "the TCP seam counter must stay untouched");
    }

    /// Refusal, unreachability and timeout demand different fixes, so they must never collapse into
    /// one another. This is the distinction the Engine panel could not previously draw.
    #[test]
    fn the_three_causes_stay_distinguishable() {
        let refused = classify_dial_failure(Some(111));
        let unreachable = classify_dial_failure(Some(101));
        let timed_out = classify_dial_failure(Some(110));
        assert_ne!(refused, unreachable, "a refused peer is NOT an unreachable one");
        assert_ne!(timed_out, refused, "a silent drop is NOT a refusal");
        assert_ne!(timed_out, unreachable, "a timeout is NOT a missing route");
    }

    /// TOTALITY over a realistic errno range, plus `None`: every input classifies, and the bucket
    /// tallies are exactly what the Lean sweep proves (1 refused, 3 unreachable, 1 timed out, the
    /// rest Other). Mirrors `exhaustive_sweep_over_the_errno_range`.
    #[test]
    fn every_errno_in_range_lands_in_exactly_one_bucket() {
        let (mut refused, mut unreachable, mut timed_out, mut other) = (0u32, 0u32, 0u32, 0u32);
        for errno in 0..=140i32 {
            match classify_dial_failure(Some(errno)) {
                DialFailure::Refused => refused += 1,
                DialFailure::Unreachable => unreachable += 1,
                DialFailure::TimedOut => timed_out += 1,
                DialFailure::Other => other += 1,
            }
        }
        assert_eq!(refused, 1, "exactly ECONNREFUSED");
        assert_eq!(unreachable, 3, "ENETUNREACH + EHOSTUNREACH + EAFNOSUPPORT");
        assert_eq!(timed_out, 1, "exactly ETIMEDOUT");
        assert_eq!(other, 136, "every remaining code falls to the catch-all");
        // THE PARTITION: the four buckets account for every input, none lost, none double-counted.
        assert_eq!(
            refused + unreachable + timed_out + other,
            141,
            "the buckets MUST sum to the number of inputs -- an uncounted failure is the exact \
             blind spot this classification exists to remove"
        );
    }

    /// Errnos far outside the named set still classify rather than panicking or being dropped --
    /// including negative and extreme values a hostile or exotic platform could produce.
    #[test]
    fn out_of_range_errnos_still_classify() {
        for errno in [-1i32, 0, 4095, i32::MIN, i32::MAX] {
            assert_eq!(
                classify_dial_failure(Some(errno)),
                DialFailure::Other,
                "errno {errno} must fall to the catch-all, never vanish"
            );
        }
    }
}

#[cfg(test)]
mod rtt_display_law_tests {
    use super::rtt_display_ms;

    /// The exact case MEASURED on the AVD: a live TCP flow that had moved 998 B and lived 23 s
    /// rendered `rtt 0ms`, because `round()` collapsed a sub-millisecond sample onto the value
    /// `forwarder_dashboard.slint:44` reserves as impossible.
    #[test]
    fn a_sub_millisecond_sample_never_reports_zero() {
        assert_eq!(rtt_display_ms(0.3), 1, "the AVD case: 0.3ms must floor to 1, not 0");
        assert_eq!(rtt_display_ms(0.9), 1, "the icmp truncation case");
        assert_eq!(rtt_display_ms(0.000_1), 1);
        assert_eq!(rtt_display_ms(0.0), 1, "even an exactly-zero reading is not the sentinel");
    }

    /// The floor must not flatten real readings — this is the non-vacuity guard.
    #[test]
    fn an_ordinary_sample_is_passed_through_untouched() {
        assert_eq!(rtt_display_ms(240.0), 240, "the RTT this device actually measures");
        assert_eq!(rtt_display_ms(1.4), 1);
        assert_eq!(rtt_display_ms(1.6), 2);
        assert_eq!(rtt_display_ms(1_000_000.0), 1_000_000);
    }

    /// A clock that ran backwards, or produced nonsense, is UNMEASURED — never fabricated as fast.
    #[test]
    fn a_bad_reading_is_unmeasured_not_fast() {
        assert_eq!(rtt_display_ms(-1.0), -1);
        assert_eq!(rtt_display_ms(-0.000_1), -1);
        assert_eq!(rtt_display_ms(f64::NAN), -1, "NaN fails every ordering test - matched by is_finite");
        assert_eq!(rtt_display_ms(f64::INFINITY), -1);
        assert_eq!(rtt_display_ms(f64::NEG_INFINITY), -1);
    }

    /// Saturation: an absurd magnitude clamps to i32::MAX rather than wrapping negative.
    #[test]
    fn an_absurd_magnitude_saturates_and_never_wraps() {
        assert_eq!(rtt_display_ms(1e18), i32::MAX);
        assert_eq!(rtt_display_ms(f64::MAX), i32::MAX);
    }

    /// THE INVARIANT ITSELF, swept: 0 is unreachable from the entire domain, and every output
    /// lands in [-1, i32::MAX]. Proved for ALL inputs in `Proofs/RttDisplay.lean`; this sweep is
    /// the implementation-side echo of that theorem.
    #[test]
    fn zero_is_unreachable_and_the_band_holds() {
        let mut probes: Vec<f64> = vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY, f64::MAX, f64::MIN];
        let mut x = -5.0f64;
        while x < 5.0 {
            probes.push(x);
            x += 0.01;
        }
        for p in [0.4999, 0.5, 0.5001, 1e9, 2147483646.0, 2147483647.0, 2147483648.0] {
            probes.push(p);
        }
        for p in probes {
            let v = rtt_display_ms(p);
            assert_ne!(v, 0, "0 is the reserved impossible value, produced by {p}");
            assert!((-1..=i32::MAX).contains(&v), "out of band: {v} from {p}");
        }
    }
}

#[cfg(test)]
mod tun_mtu_headroom_tests {
    //! The ERR_CONNECTION_CLOSED guard, executed. These mirror the theorems in
    //! `D:/Lean/proofs/Proofs/TunMtuHeadroom.lean` one-for-one: the theorems SETTLE the
    //! properties for every `Int`, these confirm the Rust actually implements the model that
    //! was proved (a proof about a mis-transcribed bound would be worthless).
    use super::{clamp_tun_mtu, TUN_MTU_CEILING, TUN_MTU_FLOOR};

    /// `clamp_fixes_the_shipped_defect` — the 1500 that shipped folds to 1400. If this test
    /// ever passes for the wrong reason, the three-week bug is back.
    #[test]
    fn the_shipped_defect_is_repaired() {
        assert_eq!(clamp_tun_mtu(1500), 1400);
    }

    /// `the_old_guard_admitted_the_defect` — the NEGATIVE CONTROL. The replaced guard was
    /// `mtu.max(64)`, a floor only; it passed 1500 straight through. Asserting the old
    /// behaviour here is what proves the new guard is doing something rather than agreeing
    /// with what was already there.
    #[test]
    fn the_old_floor_only_guard_would_have_admitted_it() {
        let old_guard = |m: i32| m.max(64) as usize;
        assert_eq!(old_guard(1500), 1500, "the old guard let the defect through");
        assert_ne!(old_guard(1500), clamp_tun_mtu(1500), "the guards must disagree");
    }

    /// `clamp_never_exceeds_ceiling` + `clamp_never_below_floor`, swept over the whole
    /// plausible range including negatives — the executable twin of the Lean `sweepOk`.
    #[test]
    fn every_input_lands_in_the_window() {
        for r in -100i32..=9000 {
            let c = clamp_tun_mtu(r);
            assert!(c >= TUN_MTU_FLOOR, "{r} clamped below the floor: {c}");
            assert!(c <= TUN_MTU_CEILING, "{r} clamped above the ceiling: {c}");
        }
    }

    /// `headroom_is_always_positive` — strictly under a 1500 B Ethernet path for EVERY input,
    /// which is the property whose violation was the bug.
    #[test]
    fn headroom_is_always_positive() {
        for r in [-2147483648i32, -1, 0, 64, 1200, 1400, 1401, 1500, 9000, 2147483647] {
            assert!(clamp_tun_mtu(r) < 1500, "no headroom for requested {r}");
        }
    }

    /// A negative `i32` must NOT wrap into an enormous buffer through `as usize` — the same
    /// class of bug in the opposite direction.
    #[test]
    fn negatives_fold_to_the_floor_instead_of_wrapping() {
        assert_eq!(clamp_tun_mtu(-1), TUN_MTU_FLOOR);
        assert_eq!(clamp_tun_mtu(i32::MIN), TUN_MTU_FLOOR);
        assert_eq!(clamp_tun_mtu(0), TUN_MTU_FLOOR);
    }

    /// `clamp_is_idempotent` — clamping a clamped value never moves it again.
    #[test]
    fn the_clamp_is_idempotent() {
        for r in [-5i32, 0, 64, 100, 1399, 1400, 1401, 1500, 9000] {
            let once = clamp_tun_mtu(r);
            let twice = clamp_tun_mtu(once as i32);
            assert_eq!(once, twice, "not idempotent at {r}");
        }
    }

    /// `clamp_is_the_identity_inside_the_window` — a legitimate configuration is never
    /// silently degraded.
    #[test]
    fn values_inside_the_window_pass_through_untouched() {
        for r in [65i32, 576, 1200, 1280, 1399, 1400] {
            assert_eq!(clamp_tun_mtu(r), r as usize, "{r} was altered");
        }
    }

    /// `clamp_is_monotone` — asking for more never yields less.
    #[test]
    fn the_clamp_is_monotone() {
        let mut prev = clamp_tun_mtu(-200);
        for r in -199i32..=2000 {
            let c = clamp_tun_mtu(r);
            assert!(c >= prev, "clamp inverted between {} and {r}", r - 1);
            prev = c;
        }
    }
}
