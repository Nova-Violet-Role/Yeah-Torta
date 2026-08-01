/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#![forbid(unsafe_code)]

//! R4 (P12 step-1.5) — **static local records** (the dnsmasq `--address=` / `host-record` /
//! `--addn-hosts` analogue), answered LOCALLY with **ZERO egress**.
//!
//! dnsmasq lets a user pin a name to an address — `address=/printer.home.arpa/192.168.1.50`,
//! `host-record`, or an `/etc/hosts`-style `--addn-hosts` file — so that name resolves to the pinned
//! IP without ever leaving the device. This module is the clean-room of that BEHAVIOUR (we read the
//! dnsmasq man-page semantics, never vendor the C): a user-pinned `name → {A/AAAA, ttl}` store, a
//! lookup consulted at the **step-1.5 seam**, and a host-file importer that REUSES the blocklist line
//! shape (the LAW: never a 2nd scanner).
//!
//! ## Where it runs (the seam) — BEFORE never-forward
//!
//! [`local_answer_if_pinned`] is consulted at the **step-1.5 seam** in
//! [`super::Resolver::resolve_inner`] — AFTER the block-check (`mod.rs:310`), and **BEFORE**
//! [`super::never_forward::local_answer_if_never_forward`] (`mod.rs:321`). The ordering is
//! load-bearing: a user who pins `printer.home.arpa → 192.168.1.50` wants that POSITIVE answer, not the
//! never-forward NXDOMAIN that branch-2 (`never_forward.rs:124-126`) would otherwise synthesize for a
//! `.home.arpa` name with "no local record." This module IS the local record — so it answers first, and
//! a `None` falls through to never-forward exactly as before. A `Some(resp)` short-circuits the resolve:
//! the synthesized positive answer returns immediately and the pool / cache / step-4 validate are
//! provably never touched (the egress is unreachable code past the early `return`).
//!
//! ## Synthesis — the R1 keystone, inlined until R1 lands
//!
//! A positive A/AAAA answer is forged from the query bytes already in hand via [`synth_address`] — the
//! **exact** compression-pointer answer shape the cache test (`cache.rs:348`) and the rebind path
//! (`mod.rs`) already forge: owner = `0xC0 0x0C` (a pointer to the question at offset 12), then
//! TYPE(A=1/AAAA=28) + CLASS=IN + TTL + RDLENGTH(4|16) + IP RDATA, with QR=1, RCODE=0(NOERROR),
//! ANCOUNT=N, and **NSCOUNT=ARCOUNT=0, no OPT** so [`crate::dns::validate_response`]'s
//! full-consumption walk (`dns.rs:411`) accepts it with zero trailing bytes.
//!
//! > **R1 seam note (EIDOLON):** the SSOT §2 R1 lands a crate-wide `dns::build_address_response(query,
//! > ips, ttl)` as the shared synthesis primitive (`dns.rs:138`, beside `build_nxdomain_response`).
//! > Until that keystone lands, [`synth_address`] here is the self-contained equivalent so this module
//! > compiles + tests GREEN standalone (additive, dead-code-until-wired — the `.so` stays
//! > byte-identical). When R1 lands, [`synth_address`]'s body collapses to a one-line call to
//! > `crate::dns::build_address_response` (same wire output, by construction); the lookup/store/parser
//! > above are unaffected.
//!
//! ## Privacy law (T20)
//!
//! The only response this can produce is a locally-synthesized positive answer built from the query
//! bytes already in hand plus a user-pinned IP — it NEVER constructs, holds, or forwards an upstream
//! query. It cannot introduce a new leak. The store holds only user-supplied pins; no qname/IP is ever
//! logged or egressed.
//!
//! ## Invariants
//!
//! Pure `std::net` (`Ipv4Addr`/`Ipv6Addr`/`IpAddr`) + `crate::dns` — **no new crate dep**,
//! `#![forbid(unsafe_code)]`, additive. The pinned store is bounded by [`MAX_LABELS`] per name (mirrors
//! `blocklist.rs`/`never_forward.rs:74`/`routing.rs:56`) so a hostile pin name cannot overflow the
//! walks.
//!
//! ## The store is PROCESS-GLOBAL (D33a — the wired form)
//!
//! The pin store was born `thread_local!` while the module shipped dormant. WIRED (the lib.rs
//! `resolver_local_records_*` exports + the Kotlin editor), that posture would be a correctness bug:
//! the control plane pins from a Kotlin/binder thread while `resolve_inner` reads from the datapath
//! threads — a thread-local store would leave every datapath thread EMPTY forever, no pin ever
//! answered. So the store is ONE process-global `RwLock<PinStore>` (uncontended read per A/AAAA
//! query, control-plane writes rare) behind a relaxed [`PIN_GAUGE`] emptiness gate: with ZERO pins
//! (the dominant posture) the step-1.5 seam costs ONE relaxed atomic load — cheaper than the old
//! per-thread `RefCell` borrow — and never touches the lock. Lock poison recovers via `into_inner`
//! (the crate idiom, D22): the store is internally consistent after every mutator.
//!
//! Durable persistence (RAM⊗NAND): the user's hosts-text lives in the integrity-framed
//! `resolver-local-records` [`crate::runtime_tier::DurableTier`] record — [`persist_text`] /
//! [`load_text`] — rehydrated at boot (RuntimeTierManager pillar 6) and re-applied live on every
//! editor save. No hot-path write: the resolve seam only ever READS the store.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{OnceLock, RwLock};

use crate::dns;

/// DNS A qtype (RFC 1035 §3.2.2). `pub(crate)` since #66-A: `resolver::resolve_uncloaked_addrs` builds
/// its address queries from the SAME two constants this module cloaks on — one authority, so a splice
/// can never ask for a qtype the cloak does not recognise.
pub(crate) const QTYPE_A: u16 = 1;
/// DNS AAAA qtype (RFC 3596 §2.1).
pub(crate) const QTYPE_AAAA: u16 = 28;
/// DNS CLASS IN (RFC 1035 §3.2.4).
const CLASS_IN: u16 = 1;

/// The fixed offset of the question in a standard query — the target of the `0xC0 0x0C` answer-owner
/// compression pointer (12-byte header, then the question). Mirrors `cache.rs:348` / `mod.rs`.
const QUESTION_OFFSET: u16 = 0x000C;

/// The durable-record name for the user's hosts-text under the shared runtime-tier root — the
/// `resolver-cache` / `resolver-rotation` naming family (RAM⊗NAND, D33a).
const DURABLE_NAME: &str = "resolver-local-records";

/// Per-name label cap — mirrors `never_forward.rs:74` / `blocklist.rs` / `routing.rs:56` (`MAX_LABELS`).
/// A pin name with more labels than this is rejected at insert and never matched, so the bounded
/// `HashMap` lookup (exact-name, not a trie walk) cannot be fed an unbounded name.
const MAX_LABELS: usize = 127;

/// DNS name length cap (RFC 1035 §3.1) — mirrors `blocklist.rs` `MAX_NAME_LEN`. A pin name longer than
/// this is rejected at insert.
const MAX_NAME_LEN: usize = 255;

// ===================================================================================================
// The step-1.5 oracle.
// ===================================================================================================

/// The step-1.5 local-record oracle. Returns `Some(positive_bytes)` when `qname`/`qtype` is a
/// user-pinned record that must be answered LOCALLY (so the caller short-circuits BEFORE never-forward
/// / cache / routing / egress), or `None` when the query has no pin and should fall through to the
/// never-forward guard and the normal resolve ladder.
///
/// Only `A`(1) and `AAAA`(28) queries can hit a pin: a pinned name answers its A query with its pinned
/// IPv4 set and its AAAA query with its pinned IPv6 set. A pin name queried for a type it has no record
/// of (e.g. an AAAA query for an IPv4-only pin) returns `None` → falls through (the name is then
/// answered by never-forward / upstream, never wrongly NODATA'd here). A non-A/AAAA qtype (PTR/TXT/…)
/// always returns `None` — local pins are address records only.
///
/// `qname` is expected already lowercased + trailing-dot-stripped (as `dns::parse_question` /
/// `dns::read_name` produce, `dns.rs:31-33`); the store is keyed lowercase so the match is exact. Pure,
/// never panics: a malformed query (so `synth_address` cannot echo a question) yields `None` rather than
/// a denial.
///
/// PRIVACY LAW (T20): the only response this can produce is a locally-synthesized positive answer built
/// from the query bytes already in hand plus a user-pinned IP — it NEVER egresses, NEVER reaches the
/// pool. It cannot introduce a new leak.
pub fn local_answer_if_pinned(query: &[u8], qname: &str, qtype: u16) -> Option<Vec<u8>> {
    // Address records only — a PTR/TXT/etc. for a pinned name is not ours to answer (fall through).
    if qtype != QTYPE_A && qtype != QTYPE_AAAA {
        return None;
    }

    // Emptiness fast-gate (D33a): with zero pins — the dominant posture — the seam costs ONE relaxed
    // atomic load and never touches the store lock.
    if PIN_GAUGE.load(Ordering::Relaxed) == 0 {
        return None;
    }

    let record = lookup_pinned(qname)?;
    // Select the address family matching the qtype; a pin with no record of that family → None
    // (fall through, never a local NODATA).
    let ttl = record.ttl;
    match qtype {
        QTYPE_A if !record.a.is_empty() => {
            let ips: Vec<IpAddr> = record.a.iter().copied().map(IpAddr::V4).collect();
            synth_address(query, &ips, ttl)
        }
        QTYPE_AAAA if !record.aaaa.is_empty() => {
            let ips: Vec<IpAddr> = record.aaaa.iter().copied().map(IpAddr::V6).collect();
            synth_address(query, &ips, ttl)
        }
        _ => None, // pinned name, but no record of the queried family → fall through
    }
}

/// Synthesize a positive A/AAAA answer pointing a watched-CDN host at the tun cloak sentinel — the
/// Centauri DNS-plane interception (P9 Centauri slice 2, retargeted by the #65 seam). `A`(1) →
/// [`CLOAK_SENTINEL_V4`] (`10.1.10.3`), `AAAA`(28) → [`CLOAK_SENTINEL_V6`], TTL `0`
/// (do-not-cache, so disarming the cloak takes effect on the very next query — never a stale sentinel
/// pin lingering in a client cache). This is the LocalCDN→Centauri redirect SEMANTICS rebuilt at the DNS
/// layer: a query for a watched CDN host is answered LOCALLY so the request lands on the in-app loopback
/// mirror instead of the real CDN. REUSES [`synth_address`] (the ONE synthesizer — REUSE-law: the mirror
/// module never re-forges DNS wire; it only decides WHICH hosts via `mirror::localcdn::is_cdn_host`, the
/// resolver synthesizes via this single keystone).
///
/// `None` for a non-A/AAAA qtype (PTR/TXT/HTTPS/SVCB/… fall through — only address records are cloaked, so
/// a watched host's non-address query resolves normally) or a malformed query (no question to echo).
///
/// PRIVACY LAW (T20): the only response this can produce is a locally-synthesized loopback answer built
/// from the query bytes already in hand — ZERO egress, no qname/IP logged. The caller gates it behind the
/// default-off `CENTAURI_CLOAK` toggle so arming the cloak is always the user's explicit opt-in.
pub(crate) fn synth_loopback_answer(query: &[u8], qtype: u16) -> Option<Vec<u8>> {
    match qtype {
        QTYPE_A => synth_address(query, &[IpAddr::V4(CLOAK_SENTINEL_V4)], 0),
        QTYPE_AAAA => synth_address(query, &[IpAddr::V6(CLOAK_SENTINEL_V6)], 0),
        // Address records only — a PTR/TXT/HTTPS/… query of a watched host is not cloaked (fall through).
        _ => None,
    }
}

/// ★ #65 seam — the CANONICAL typed cloak-sentinel pair (the string twin lives in
/// `mirror::localcdn::CLOAK_SENTINEL_IP`, kept equal by test). Cloaked A answers point here instead of
/// `127.0.0.1`: loopback flows never enter the tun (the old value stranded every cloaked fetch —
/// CDN SAW stayed 0), while `10.1.10.3` sits beside the tun address (`vpn4` default `10.1.10.1/32`) and
/// the virtual DNS (`VPN_VIRTUAL_DNS_IP = 10.1.10.2`, VpnBuilder.kt:394), so under the ARMED forwarder's
/// full-capture routes every sentinel packet lands in `forwarder/run.rs`, which splices it to the
/// mirror's real bound port. Declared here (always-compiled) because BOTH feature-gated consumers — the
/// `mirror` cloak synth above and the `netstack` forwarder splice — must see one authority.
pub(crate) const CLOAK_SENTINEL_V4: Ipv4Addr = Ipv4Addr::new(10, 1, 10, 3);

/// The v6 twin — beside the `vpn6` default `fd00:1:fd00:1:fd00:1:fd00:1/128` (captured by the ARMED
/// `::/0` route). AAAA must answer a sentinel too: `None`/fall-through would resolve the REAL CDN AAAA
/// upstream and the fetch would leak over v6, silently bypassing the whole seam.
pub(crate) const CLOAK_SENTINEL_V6: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 1, 0xfd00, 1, 0xfd00, 1, 0xfd00, 3);

// ===================================================================================================
// R1-keystone synthesis (inlined until `dns::build_address_response` lands — see the R1 seam note).
// ===================================================================================================

/// Forge a positive A/AAAA response to `query` from `ips` at `ttl` — the R1 synthesis keystone,
/// inlined here until `crate::dns::build_address_response` lands (then this collapses to a call to it).
///
/// The wire is the EXACT shape `build_nxdomain_response` (`dns.rs:138`) and the cache positive-answer
/// helper (`cache.rs:338-355`) forge: echo the question, flip QR, set RCODE=0(NOERROR), RA=1, set
/// ANCOUNT to the record count, then append one answer per IP whose owner is the compression pointer
/// `0xC0 0x0C` to the question at offset 12. NSCOUNT/ARCOUNT stay 0 and there is NO OPT, so
/// [`crate::dns::validate_response`] accepts it with EXACTLY-zero trailing bytes (`dns.rs:411`).
///
/// `None` when `query` is malformed (no question to echo) or `ips` is empty. The IP families are mixed
/// at the caller's discretion, but [`local_answer_if_pinned`] only ever passes a single-family set so
/// the synthesized TYPE matches the query's qtype.
/// ★ THE NODATA CANVAS — NOERROR with `ANCOUNT = 0`: "this name EXISTS, it has no record of the
/// type you asked for."
///
/// Deliberately NOT NXDOMAIN. NXDOMAIN denies the NAME, and a client that hears it stops asking —
/// it will not fall back to `A`, and it may cache the denial for the whole name. NODATA denies only
/// the RRTYPE, which is exactly the truth when IPv6 egress is unusable: `example.com` is real, this
/// network just cannot carry a v6 route to it.
///
/// Used by the AAAA-withholding seam (`resolver/mod.rs`, gated on
/// [`crate::egress::v6_should_attempt`]) so a client stops CHOOSING IPv6 on a network that refuses
/// it. MEASURED justification: suppressing the doomed DIAL cut `net_error -100` only 507 -> 502 over
/// 111 URLs while 492 dials were skipped — by then the client has already committed to a v6 socket,
/// so the closure still happens. The choice has to be prevented at the DNS answer.
pub(crate) fn synth_nodata(query: &[u8]) -> Option<Vec<u8>> {
    // Same malformed-query guard as `synth_address`: never forge a reply over a garbage question.
    let _ = dns::parse_question(query)?;
    let qend = question_end(query)?;
    if qend < 12 {
        return None;
    }
    let mut resp = query[..qend].to_vec();
    resp[2] |= 0x80; // QR = 1 (response), keep Opcode + RD
    resp[3] = (resp[3] | 0x80) & 0xF0; // RA = 1, clear Z, RCODE = NOERROR(0) -- NOT NXDOMAIN(3)
    resp[4] = 0;
    resp[5] = 1; // QDCOUNT = 1
    resp[6] = 0;
    resp[7] = 0; // ANCOUNT = 0 -- this is what makes it NODATA
    resp[8] = 0;
    resp[9] = 0; // NSCOUNT = 0
    resp[10] = 0;
    resp[11] = 0; // ARCOUNT = 0 (no OPT -> validate_response's exact-consumption walk accepts it)
    Some(resp)
}

fn synth_address(query: &[u8], ips: &[IpAddr], ttl: u32) -> Option<Vec<u8>> {
    if ips.is_empty() {
        return None;
    }
    // Malformed-query guard (defense-in-depth): the canonical `dns::parse_question` must accept the
    // query (so we never forge an answer over a garbage question), AND our bounded `question_end`
    // re-walk must agree on where the question ends so the answers append immediately after it. Either
    // rejecting → None (never a forged answer). The parsed question itself is unused beyond the guard.
    let _ = dns::parse_question(query)?;
    let qend = question_end(query)?;

    // The answer-count must fit the 16-bit ANCOUNT field; a pin with absurdly many IPs is clamped to
    // what the wire can carry (defensive — pin stores are tiny, this never trips in practice).
    let ancount = u16::try_from(ips.len()).ok()?;

    let mut resp = query[..qend].to_vec();
    resp[2] |= 0x80; // QR = 1 (response), keep Opcode + RD
    resp[3] = (resp[3] | 0x80) & 0xF0; // RA = 1, clear Z, RCODE = NOERROR(0)
    resp[4] = 0;
    resp[5] = 1; // QDCOUNT = 1
    resp[6..8].copy_from_slice(&ancount.to_be_bytes()); // ANCOUNT = ips.len()
    resp[8] = 0;
    resp[9] = 0; // NSCOUNT = 0
    resp[10] = 0;
    resp[11] = 0; // ARCOUNT = 0 (no OPT → validate_response's exact-consumption walk accepts it)

    for ip in ips {
        // Owner = compression pointer to the question (0xC0 0x0C) — the exact form cache.rs:348 forges.
        resp.extend_from_slice(&[0xC0, (QUESTION_OFFSET & 0x00FF) as u8]);
        match ip {
            IpAddr::V4(v4) => {
                resp.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE = A
                resp.extend_from_slice(&CLASS_IN.to_be_bytes()); // CLASS = IN
                resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
                resp.extend_from_slice(&v4.octets()); // 4-byte A RDATA
            }
            IpAddr::V6(v6) => {
                resp.extend_from_slice(&QTYPE_AAAA.to_be_bytes()); // TYPE = AAAA
                resp.extend_from_slice(&CLASS_IN.to_be_bytes()); // CLASS = IN
                resp.extend_from_slice(&ttl.to_be_bytes()); // TTL
                resp.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH = 16
                resp.extend_from_slice(&v6.octets()); // 16-byte AAAA RDATA
            }
        }
    }
    Some(resp)
}

/// The byte offset just past the question section of `query` (12-byte header + QNAME + QTYPE + QCLASS),
/// so [`synth_address`] knows where to append answers. `None` on a malformed question — the same bound
/// `dns::parse_question` enforces. A small local re-walk of the QNAME labels (header + labels + root +
/// 4 fixed bytes) rather than reaching into the private `parse_question_full` end-position (REUSE-law:
/// no reach into a private parser; the walk is bounded by [`MAX_NAME_LEN`]).
fn question_end(query: &[u8]) -> Option<usize> {
    if query.len() < 12 {
        return None;
    }
    let mut pos = 12usize; // past the fixed header
    let mut walked = 0usize;
    loop {
        let len = *query.get(pos)? as usize;
        // A compression pointer must never appear in a QUESTION's QNAME — reject (malformed).
        if len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            break; // root label — QNAME complete
        }
        walked += len + 1;
        if walked > MAX_NAME_LEN {
            return None; // QNAME runs past the DNS name bound — malformed
        }
        pos += len;
        if pos > query.len() {
            return None; // label runs off the end
        }
    }
    // QTYPE(2) + QCLASS(2) follow the QNAME root label.
    let end = pos + 4;
    if end > query.len() {
        return None;
    }
    Some(end)
}

// ===================================================================================================
// The pinned-record store — user `name → {A set, AAAA set, ttl}`, exact-name keyed, bounded.
// ===================================================================================================

/// One pinned local record: the A (IPv4) and AAAA (IPv6) sets for a single name, plus its TTL. A pin
/// may carry only A, only AAAA, or both; the empty set for a family means "no record of that family"
/// (so an AAAA query for an A-only pin falls through, never a local NODATA).
#[derive(Clone, Default)]
struct LocalRecord {
    a: Vec<Ipv4Addr>,
    aaaa: Vec<Ipv6Addr>,
    ttl: u32,
}

/// The user-pinned local-record store: an exact-name `HashMap` (NOT a suffix trie — a pin is an exact
/// name, `printer.home.arpa`, not a zone). Keyed lowercase + dot-normalized so the lookup matches the
/// `qname` shape `dns::read_name` produces. Bounded per name by [`MAX_LABELS`]/[`MAX_NAME_LEN`] at
/// insert so a hostile pin name cannot bloat the map key or a later walk.
#[derive(Default)]
struct PinStore {
    by_name: HashMap<Box<str>, LocalRecord>,
}

impl PinStore {
    /// An empty store (the dormant default — no pins until the JNI/Kotlin seam imports the user's).
    fn empty() -> Self {
        PinStore {
            by_name: HashMap::new(),
        }
    }

    /// Pin `ip` to `name` at `ttl`. The name is canonicalized (lowercased, trailing-dot-stripped, empty
    /// labels dropped) the same way `blocklist::normalize_domain`-shape does (REUSE-law: clone the
    /// shape, not the private fn). An empty / over-long / over-deep name is dropped (never panics,
    /// never an unbounded key) — returns `false` so the importer can count it honestly. A repeated
    /// `(name, family)` APPENDS (a name may pin several A records).
    fn pin(&mut self, name: &str, ip: IpAddr, ttl: u32) -> bool {
        let Some(canon) = canonicalize_name(name) else {
            return false; // empty / over-bound name → drop
        };
        let record = self.by_name.entry(canon.into()).or_default();
        record.ttl = ttl;
        match ip {
            IpAddr::V4(v4) => {
                if !record.a.contains(&v4) {
                    record.a.push(v4);
                }
            }
            IpAddr::V6(v6) => {
                if !record.aaaa.contains(&v6) {
                    record.aaaa.push(v6);
                }
            }
        }
        true
    }

    /// Look up the pinned record for `qname` (exact-name, already canonical). `None` when the name is
    /// not pinned. `O(1)` average (`HashMap`), never a walk, never panics.
    fn lookup(&self, qname: &str) -> Option<&LocalRecord> {
        if qname.is_empty() {
            return None;
        }
        self.by_name.get(qname)
    }

    /// Import an `/etc/hosts`-style `--addn-hosts` file (or any `<ip> <name>...` source) by REUSING the
    /// blocklist line shape — NOT a 2nd parser (the LAW). Each line is split into a leading IP token and
    /// the trailing name(s), exactly as `blocklist::parse_line` (`blocklist.rs:375`) detects a host-file
    /// sink line: a leading token that parses as an `IpAddr` plus one or more names → pin every name to
    /// that IP. Comment (`#`/`!`) and blank lines are skipped silently. Lines with no leading IP, or no
    /// name, or an over-bound name are counted `skipped` (the editor's honest feedback). Returns
    /// `(applied_records, skipped_lines)`.
    fn import_hosts(&mut self, text: &str, ttl: u32) -> (usize, usize) {
        let mut applied = 0usize;
        let mut skipped = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('!') {
                continue; // comment/blank — not an error, never counted
            }
            match parse_hosts_line(line) {
                Some((ip, names)) => {
                    let mut any = false;
                    for name in names {
                        if self.pin(name, ip, ttl) {
                            applied += 1;
                            any = true;
                        }
                    }
                    if !any {
                        skipped += 1; // every name on the line was over-bound/empty
                    }
                }
                None => skipped += 1,
            }
        }
        (applied, skipped)
    }
}

/// Parse one `/etc/hosts`-style line into `(sink_ip, [names])`, or `None` for a comment/blank/no-sink
/// line. This is the **blocklist `parse_line` host-file shape** (`blocklist.rs:375-384`,
/// `is_host_sink` `blocklist.rs:414`) reused verbatim in structure: trim, skip `#`/`!`/blank, take the
/// leading whitespace-delimited token, and IFF it parses as an `IpAddr` treat the rest of the line as
/// the name(s) it sinks. We clone the SHAPE (the private `blocklist::parse_line` returns a single
/// blocklist domain and cannot be called from here) — the only honest reuse, exactly the posture
/// `never_forward.rs:52` / `routing.rs:30-34` took.
fn parse_hosts_line(line: &str) -> Option<(IpAddr, Vec<&str>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return None;
    }
    // Drop any inline comment tail (`<ip> name # note`).
    let line = line.split('#').next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    // Leading token must be a sink IP (the `blocklist::is_host_sink` test, `blocklist.rs:414`).
    let (first, rest) = line.split_once(char::is_whitespace)?;
    let ip = first.parse::<IpAddr>().ok()?;
    // The remaining whitespace-delimited tokens are the names this IP sinks (one or many).
    let names: Vec<&str> = rest.split_whitespace().filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        return None; // a sink IP with no name is not an address pin
    }
    Some((ip, names))
}

/// Canonicalize a pin name: trim, strip a trailing dot, lowercase, drop empty labels, then bound-check.
/// `None` for an empty / over-long / over-deep name. Mirrors the `blocklist::normalize_domain` shape
/// (`blocklist.rs:355-361`) so a pinned name keys the same way a `qname` from `dns::read_name` arrives
/// (lowercased, no trailing dot) — guaranteeing the exact-name lookup matches. REUSE-law: clone the
/// shape, never call the private fn.
fn canonicalize_name(name: &str) -> Option<String> {
    let lowered = name.trim().trim_end_matches('.').to_lowercase();
    let canon: String = lowered
        .split('.')
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    if canon.is_empty() || canon.len() > MAX_NAME_LEN {
        return None;
    }
    if canon.split('.').count() > MAX_LABELS {
        return None;
    }
    Some(canon)
}

/// The LIVE pinned-NAME gauge — the step-1.5 emptiness fast-gate AND the dashboard count read.
/// Refreshed from the store size under the write lock by every mutator ([`with_store_mut`] is the ONE
/// maintainer — no drift); read relaxed on the hot path (a stale read costs at worst one harmless
/// lock-take or one query falling through mid-swap — never a wrong answer).
static PIN_GAUGE: AtomicUsize = AtomicUsize::new(0);

/// The process-global pinned-record store (see the module doc: a thread-local here would hide every
/// control-plane pin from the datapath threads). `OnceLock` because `HashMap::new` is not const.
fn pinned() -> &'static RwLock<PinStore> {
    static PINNED: OnceLock<RwLock<PinStore>> = OnceLock::new();
    PINNED.get_or_init(|| RwLock::new(PinStore::empty()))
}

/// Look up `qname` and return an OWNED clone of the pinned record, so the read guard never escapes
/// (the borrow lives exactly as long as the lookup). `None` when not pinned. Poison recovers via
/// `into_inner` (the crate idiom): every mutator leaves the store internally consistent.
fn lookup_pinned(qname: &str) -> Option<LocalRecord> {
    let guard = pinned().read().unwrap_or_else(|e| e.into_inner());
    guard.lookup(qname).cloned()
}

/// Run `f` under the store WRITE lock, then refresh [`PIN_GAUGE`] from the store size — the gauge is
/// maintained ONLY here (one law, no drift). Control-plane only; the resolve seam never calls this.
fn with_store_mut<R>(f: impl FnOnce(&mut PinStore) -> R) -> R {
    let mut guard = pinned().write().unwrap_or_else(|e| e.into_inner());
    let out = f(&mut guard);
    PIN_GAUGE.store(guard.by_name.len(), Ordering::Relaxed);
    out
}

// ===================================================================================================
// Control-plane API — the lib.rs `resolver_local_records_*` exports (the Kotlin editor + the boot
// rehydrate, D33a) drive these. Never the resolve hot path.
// ===================================================================================================

/// Pin a single user record `name → ip` at `ttl` (a dnsmasq `--address=/name/ip` / `host-record`) on
/// the process-global store. In production the editor feeds [`set_records`] (whole-text replace, which
/// pins through the SAME `PinStore::pin`); this single-pin primitive is kept for the tests (and a
/// future per-row editor) — `cfg(test)` so the shipped `.so` carries zero dead code.
#[cfg(test)]
pub fn pin_record(name: &str, ip: IpAddr, ttl: u32) {
    with_store_mut(|store| {
        store.pin(name, ip, ttl);
    });
}

/// Import an `/etc/hosts`-style `--addn-hosts` file body ADDITIVELY (existing pins stay), pinning
/// every `<ip> <name>...` line at `ttl`. Production saves go through [`set_records`] (replace
/// semantics — what you see is what is pinned), which drives the SAME `PinStore::import_hosts`;
/// `cfg(test)` for the same zero-dead-code reason as [`pin_record`].
#[cfg(test)]
pub fn import_addn_hosts(text: &str, ttl: u32) -> (usize, usize) {
    with_store_mut(|store| store.import_hosts(text, ttl))
}

/// REPLACE the whole store with the pins parsed from `text` — the editor SAVE semantic (what you see is
/// what is pinned: a deleted line unpins). One write lock, atomic swap; the gauge follows. Returns
/// `(names, applied_records, skipped_lines)`.
pub fn set_records(text: &str, ttl: u32) -> (usize, usize, usize) {
    with_store_mut(|store| {
        store.by_name.clear();
        let (applied, skipped) = store.import_hosts(text, ttl);
        (store.by_name.len(), applied, skipped)
    })
}

/// The live pinned-NAME count (the dashboard gauge) — one relaxed load, never locks.
pub fn records_count() -> usize {
    PIN_GAUGE.load(Ordering::Relaxed)
}

/// Persist the editor's hosts-text into the integrity-framed `resolver-local-records` durable record
/// (RAM⊗NAND write-through — control-plane, off the resolve path). Empty/blank text CLEARS the record
/// (nothing to rehydrate — byte-identical to a fresh install). `false` = the write was refused.
pub fn persist_text(dir: &str, text: &str) -> bool {
    let tier =
        crate::runtime_tier::DurableTier::with_dir(std::path::PathBuf::from(dir), DURABLE_NAME);
    if text.trim().is_empty() {
        tier.clear();
        return true;
    }
    tier.write_through(text.as_bytes()).is_ok()
}

/// Load the persisted hosts-text (`None` = cold / cleared / corrupt — the integrity frame rejects a
/// torn record; non-UTF-8 degrades to `None`, never a panic).
pub fn load_text(dir: &str) -> Option<String> {
    let tier =
        crate::runtime_tier::DurableTier::with_dir(std::path::PathBuf::from(dir), DURABLE_NAME);
    let bytes = tier.rehydrate()?;
    String::from_utf8(bytes).ok()
}

/// The GLOBAL-store test guard — the process-global store is shared by every parallel test thread in
/// this binary, so the handful of tests that mutate it (here and in `lib.rs`'s D33 export tests)
/// serialize on this lock; store-local `PinStore` tests never need it.
#[cfg(test)]
pub(crate) fn test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns;

    /// Forge a minimal DNS query wire for `qname`/`qtype` so the synthesized answer has a real question
    /// to echo — reuses the crate's own `dns::build_query` (the canonical builder, no hand-rolled wire).
    fn query_for(qname: &str, qtype: u16) -> Vec<u8> {
        dns::build_query(0x1234, qname, qtype)
    }

    /// Assert `resp` is a structurally-valid POSITIVE answer for `query`: QR=1, RCODE=0(NOERROR),
    /// ANCOUNT==expected, ARCOUNT==0, and it `validate_response`s as a legitimate reply to the question
    /// (so a real client would accept it) AND `answer_records` reads back the synthesized records.
    fn assert_is_positive(query: &[u8], resp: &[u8], expected_answers: usize) {
        // QR == 1 (response)
        assert_eq!(resp[2] & 0x80, 0x80, "QR must be 1 (response)");
        // RCODE == 0 (NOERROR — a positive answer, not a denial)
        assert_eq!(resp[3] & 0x0F, 0, "RCODE must be NOERROR(0)");
        // ANCOUNT == expected
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]) as usize,
            expected_answers,
            "ANCOUNT must equal the pinned record count"
        );
        // ARCOUNT == 0 (no OPT — the validate exact-consumption walk requires zero trailing bytes)
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "ARCOUNT must be 0 (no OPT, no trailing section)"
        );
        // It validates as a genuine reply to this exact question (anti-poisoning keystone accepts it).
        assert!(
            dns::validate_response(query, resp).is_ok(),
            "the synthesized positive answer must validate against its own query"
        );
        // And the answer skimmer reads the synthesized records back.
        let records =
            dns::answer_records(resp).expect("answer_records must read the synthesized set");
        assert_eq!(
            records.len(),
            expected_answers,
            "answer_records must return every synthesized record"
        );
    }

    // ---- the headline R4 test: a pinned name synthesizes a positive A/AAAA, zero egress ----

    #[test]
    fn local_record_pin_synthesizes_a_aaaa_with_local_ttl_zero_egress() {
        let mut store = PinStore::empty();
        // Pin myhost.local → 10.0.0.5 (A) and an AAAA, at a local TTL.
        store.pin("myhost.local", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 120);
        store.pin(
            "myhost.local",
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 5)),
            120,
        );

        // A query → positive A synthesized (NOT a never-forward NXDOMAIN, though .local is special-use).
        let qa = query_for("myhost.local", QTYPE_A);
        let record = store
            .lookup("myhost.local")
            .expect("pin must be present")
            .clone();
        let ips_a: Vec<IpAddr> = record.a.iter().copied().map(IpAddr::V4).collect();
        let resp_a = synth_address(&qa, &ips_a, record.ttl).expect("A synthesis");
        assert_is_positive(&qa, &resp_a, 1);
        // The synthesized record carries the LOCAL ttl folded in.
        let recs = dns::answer_records(&resp_a).unwrap();
        assert_eq!(
            recs[0].ttl, 120,
            "the synthesized A carries the pin's local-ttl"
        );
        assert_eq!(recs[0].rtype, QTYPE_A, "the synthesized record is an A");

        // AAAA query → positive AAAA synthesized.
        let qaaaa = query_for("myhost.local", QTYPE_AAAA);
        let ips_aaaa: Vec<IpAddr> = record.aaaa.iter().copied().map(IpAddr::V6).collect();
        let resp_aaaa = synth_address(&qaaaa, &ips_aaaa, record.ttl).expect("AAAA synthesis");
        assert_is_positive(&qaaaa, &resp_aaaa, 1);
        let recs6 = dns::answer_records(&resp_aaaa).unwrap();
        assert_eq!(
            recs6[0].rtype, QTYPE_AAAA,
            "the synthesized record is an AAAA"
        );
    }

    #[test]
    fn pinned_name_answers_positively_through_the_oracle_not_a_denial() {
        // The full oracle path (the process-global store): pin via the control-plane API, then resolve.
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        pin_record(
            "printer.home.arpa",
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            300,
        );
        let query = query_for("printer.home.arpa", QTYPE_A);
        let resp = local_answer_if_pinned(&query, "printer.home.arpa", QTYPE_A)
            .expect("a pinned name must be answered locally (positive), not fall to never-forward");
        // The whole point of R4 ordering: a .home.arpa pin is answered POSITIVELY here, BEFORE
        // never-forward would have NXDOMAIN'd it.
        assert_is_positive(&query, &resp, 1);
        let recs = dns::answer_records(&resp).unwrap();
        assert_eq!(recs[0].rtype, QTYPE_A);
    }

    /// D33a — THE wired-form correctness pearl: a pin installed from ONE thread (the Kotlin
    /// control-plane / binder thread in production) is answered on ANOTHER thread (a datapath
    /// thread). Under the old `thread_local!` store this test FAILS (the pinning thread's store
    /// dies with it; the resolving thread sees an empty map forever); the process-global store
    /// makes the pin visible everywhere.
    #[test]
    fn pins_are_visible_across_threads_d33() {
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        std::thread::spawn(|| {
            pin_record(
                "xthread.printer.lan",
                IpAddr::V4(Ipv4Addr::new(192, 168, 7, 7)),
                60,
            );
        })
        .join()
        .expect("the control-plane pin thread must not panic");
        let query = query_for("xthread.printer.lan", QTYPE_A);
        let resp = local_answer_if_pinned(&query, "xthread.printer.lan", QTYPE_A)
            .expect("a pin from another thread MUST be visible at the resolve seam (D33a)");
        assert_is_positive(&query, &resp, 1);
    }

    #[test]
    fn unpinned_name_falls_through_no_local_answer() {
        // A name with no pin → None (control falls through to never-forward / the ladder, no egress here).
        let query = query_for("notpinned.example.com", QTYPE_A);
        assert!(
            local_answer_if_pinned(&query, "notpinned.example.com", QTYPE_A).is_none(),
            "an unpinned name must fall through, not be answered locally"
        );
    }

    #[test]
    fn non_address_qtype_falls_through() {
        // Even for a PINNED name, a PTR/TXT query is not an address record → None (fall through).
        let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
        pin_record("svc.lan", IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 60);
        let q_ptr = query_for("svc.lan", 12 /* PTR */);
        assert!(
            local_answer_if_pinned(&q_ptr, "svc.lan", 12).is_none(),
            "a non-A/AAAA query of a pinned name is not an address-pin hit"
        );
    }

    #[test]
    fn aaaa_query_of_ipv4_only_pin_falls_through_not_nodata() {
        // A pin with ONLY an A record, queried for AAAA → None (fall through), never a local NODATA.
        let mut store = PinStore::empty();
        store.pin("v4only.lan", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 60);
        // Simulate the oracle's family-select: AAAA family is empty → no synthesis.
        let record = store.lookup("v4only.lan").unwrap();
        assert!(record.a.len() == 1 && record.aaaa.is_empty());
    }

    // ---- the reuse-law test: the hosts-file import reuses the blocklist parse_line shape ----

    #[test]
    fn addn_hosts_import_reuses_blocklist_parse_line() {
        // An /etc/hosts-style body — the SAME shape blocklist::parse_line detects (leading sink IP +
        // name(s)). Comments + blanks skipped; multi-name lines pin every name.
        let hosts = "\
# a comment
10.0.0.5    myhost.local
192.168.1.1 router.box gateway.box
fd00::1     v6host.lan
! adblock-style comment
nonsense-no-ip-here
8.8.8.8 # sink IP but no name → skipped
";
        let mut store = PinStore::empty();
        let (applied, skipped) = store.import_hosts(hosts, 0);
        // 4 pins landed (myhost + router + gateway + v6host); 2 real lines skipped (no-ip line +
        // the sink-IP-no-name line); comments/blanks never counted.
        assert_eq!(applied, 4, "every parseable (name, ip) pin counted");
        assert_eq!(
            skipped, 2,
            "the two unusable non-comment lines counted skipped"
        );

        // single-name line pinned
        assert!(
            store.lookup("myhost.local").is_some(),
            "single hosts line pinned"
        );
        // multi-name line pinned BOTH names to the same IP
        let router = store.lookup("router.box").expect("router.box pinned");
        let gateway = store.lookup("gateway.box").expect("gateway.box pinned");
        assert_eq!(router.a, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(gateway.a, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        // v6 line → AAAA pin
        let v6 = store.lookup("v6host.lan").expect("v6host.lan pinned");
        assert_eq!(v6.aaaa, vec![Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)]);
        // comment + no-ip + no-name lines did NOT create pins
        assert!(store.lookup("nonsense-no-ip-here").is_none());

        // And the parse_hosts_line shape itself: a comment/blank/no-sink line → None, a sink line → Some.
        assert!(parse_hosts_line("# comment").is_none());
        assert!(parse_hosts_line("   ").is_none());
        assert!(parse_hosts_line("not-an-ip name").is_none());
        assert!(parse_hosts_line("10.0.0.1 host").is_some());
    }

    // ---- canonicalization mirrors the blocklist normalize shape (so qname keys match) ----

    #[test]
    fn pin_name_canonicalizes_like_a_qname() {
        let mut store = PinStore::empty();
        // Pinned with trailing dot + mixed case + empty labels — must key the same as the lowercased,
        // dot-stripped qname dns::read_name produces.
        store.pin("MyHost.Local.", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)), 60);
        assert!(
            store.lookup("myhost.local").is_some(),
            "a pin keyed the same canonical way a qname arrives (lowercased, no trailing dot)"
        );
    }

    #[test]
    fn over_bound_pin_name_is_dropped_not_panicked() {
        let mut store = PinStore::empty();
        // An over-deep name (more than MAX_LABELS labels) is dropped at insert, never panics.
        let deep = vec!["x"; MAX_LABELS + 50].join(".");
        store.pin(&deep, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 60);
        assert!(
            store.lookup(&deep).is_none(),
            "an over-deep pin name is dropped, not stored"
        );
        // An over-long name (> MAX_NAME_LEN bytes) is likewise dropped.
        let long = format!("{}.com", "a".repeat(MAX_NAME_LEN));
        store.pin(&long, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 60);
        assert!(
            store.lookup(&long).is_none(),
            "an over-long pin name is dropped"
        );
    }

    #[test]
    fn empty_pin_name_is_dropped() {
        let mut store = PinStore::empty();
        store.pin("", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 60);
        store.pin("...", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 60);
        assert!(
            store.by_name.is_empty(),
            "empty / dot-only pin names create no entry"
        );
    }

    #[test]
    fn multiple_a_records_for_one_name_append_not_overwrite() {
        let mut store = PinStore::empty();
        store.pin("multi.lan", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 60);
        store.pin("multi.lan", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 60);
        let rec = store.lookup("multi.lan").unwrap();
        assert_eq!(
            rec.a.len(),
            2,
            "a name may pin several A records (append, not overwrite)"
        );
        // A re-pin of the SAME IP does not duplicate it.
        store.pin("multi.lan", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 60);
        let rec2 = store.lookup("multi.lan").unwrap();
        assert_eq!(
            rec2.a.len(),
            2,
            "re-pinning the same IP does not duplicate it"
        );
    }

    #[test]
    fn nodata_is_noerror_with_no_answers_and_is_not_nxdomain() {
        let q = query_for("example.com", QTYPE_AAAA);
        let resp = synth_nodata(&q).expect("a well-formed question must yield a canvas");
        assert_eq!(resp[2] & 0x80, 0x80, "QR must be set (it is a response)");
        assert_eq!(resp[3] & 0x0F, 0, "RCODE must be NOERROR(0), never NXDOMAIN(3)");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "ANCOUNT must be 0 -- that is NODATA");
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1, "QDCOUNT must stay 1");
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0, "NSCOUNT must be 0");
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0, "ARCOUNT must be 0");
    }

    #[test]
    fn nodata_preserves_the_question_verbatim() {
        let q = query_for("cdn.example.org", QTYPE_AAAA);
        let resp = synth_nodata(&q).expect("canvas");
        assert_eq!(
            resp[12..],
            q[12..q.len()],
            "the question section must come back byte-identical, or the client cannot match it"
        );
    }

    #[test]
    fn nodata_on_a_malformed_query_yields_none_never_a_forged_reply() {
        assert!(synth_nodata(&[]).is_none(), "empty");
        assert!(synth_nodata(&[0u8; 4]).is_none(), "truncated header");
        assert!(synth_nodata(&[0xFFu8; 12]).is_none(), "header with no question");
    }

    #[test]
    fn synth_address_on_malformed_query_yields_none_not_panic() {
        // A truncated query (no parseable question) → synth returns None, never panics.
        let truncated = vec![0u8; 5];
        assert!(
            synth_address(&truncated, &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], 60).is_none(),
            "a malformed query yields None, not a forged answer or a panic"
        );
        // An empty IP set → None.
        let q = query_for("a.lan", QTYPE_A);
        assert!(synth_address(&q, &[], 60).is_none(), "no IPs → no answer");
    }

    #[test]
    fn synthesized_multi_record_answer_validates_and_skims() {
        // Several A records for one name → ANCOUNT==N, all readable, still validates.
        let q = query_for("multi.lan", QTYPE_A);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        ];
        let resp = synth_address(&q, &ips, 60).expect("multi-A synthesis");
        assert_is_positive(&q, &resp, 3);
    }

    // ---- P9 Centauri slice 2: the DNS-plane cloak synthesizes a tun-sentinel answer for a watched host ----

    #[test]
    fn centauri_cloak_synth_points_a_aaaa_at_tun_sentinel_zero_egress() {
        // A watched-CDN host's A query → a positive CLOAK_SENTINEL_V4 (10.1.10.3) answer (the
        // LocalCDN→Centauri redirect SEMANTICS rebuilt at the DNS layer); AAAA → CLOAK_SENTINEL_V6.
        // NOT loopback: 127/8 escapes the tun, the sentinel rides it. Validates as a genuine reply;
        // non-A/AAAA + malformed → None. ZERO egress (the answer is forged from the query bytes in hand).
        let qa = query_for("cdnjs.cloudflare.com", QTYPE_A);
        let a = synth_loopback_answer(&qa, QTYPE_A).expect("A → sentinel synth");
        assert_is_positive(&qa, &a, 1);
        let recs = dns::answer_records(&a).unwrap();
        assert_eq!(recs[0].rtype, QTYPE_A, "the cloak answer is an A");
        // The A RDATA is EXACTLY the v4 sentinel — the final 4 bytes of the single appended answer record.
        assert_eq!(
            &a[a.len() - 4..],
            &CLOAK_SENTINEL_V4.octets(),
            "A cloak RDATA is the 10.1.10.3 tun sentinel"
        );

        let qaaaa = query_for("cdnjs.cloudflare.com", QTYPE_AAAA);
        let aaaa = synth_loopback_answer(&qaaaa, QTYPE_AAAA).expect("AAAA → sentinel synth");
        assert_is_positive(&qaaaa, &aaaa, 1);
        // The AAAA RDATA is EXACTLY the v6 sentinel — 16 bytes.
        assert_eq!(
            &aaaa[aaaa.len() - 16..],
            &CLOAK_SENTINEL_V6.octets(),
            "AAAA cloak RDATA is the v6 tun sentinel"
        );

        // A non-address qtype (PTR) of a watched host is NOT cloaked → None (resolves normally).
        assert!(
            synth_loopback_answer(&query_for("cdnjs.cloudflare.com", 12 /* PTR */), 12).is_none(),
            "only address records are cloaked; a PTR of a watched host falls through"
        );
        // A malformed query → None (never a forged loopback over garbage).
        assert!(
            synth_loopback_answer(&[0u8; 4], QTYPE_A).is_none(),
            "a malformed query yields None, not a forged answer"
        );
    }
}
