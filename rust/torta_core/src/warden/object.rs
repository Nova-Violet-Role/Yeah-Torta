/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE WARDEN OBJECT — the stateful Rust pure-firewall pillar (the R1.x.3 Object lift).
//!
//! The Warden is a stateful pillar (alongside [`crate::beast::Beast`] and
//! [`crate::mirror::object`]) built as a `#[derive(uniffi::Object)]`: Kotlin constructs a
//! single `Arc<WardenObject>` at boot, holds the handle, arms the rule-sets + per-app matrix + universal
//! toggles (allow-by-default — no policy), drives the per-connection [`WardenObject::verdict`], and pulls a
//! [`WardenSnapshot`] for the dashboard. This closes the "inert flat free-function" gap the audit
//! flagged — the verdict engine lived in a process-global `OnceLock<Mutex<Option<Warden>>>` singleton
//! (`crate::WARDEN`) reachable ONLY through the flat `warden_stats` export + the
//! C-ABI `torta_firewall_verdict`, with NO stateful handle Kotlin could hold an `Arc` to. The Object
//! makes the engine + its armed rule-sets + matrix + toggles a LIVED accumulator the Warden manager
//! drives directly.
//!
//! ## The pattern (the stateful-Object pillar template — the NON-gated form)
//! Six-part surface, the pillar Object template (NOT the Centauri feature-gate — the Warden is
//! ALWAYS-BUILT; it ships in every feature config):
//!   1. `#[derive(uniffi::Object)] pub struct WardenObject` — interior state is `Mutex<Warden>` (std,
//!      since the crate is `#![forbid(unsafe_op_in_unsafe_fn)]` and this module is `#![forbid(unsafe_code)]`).
//!   2. `#[uniffi::constructor] fn new() -> Arc<Self>` — UniFFI Object ctors MUST return `Arc<Self>`.
//!      Cold baseline: an allow-all fail-safe engine (never bricks connectivity) + empty rule-sets/matrix/toggles.
//!   3. `#[uniffi::export] impl WardenObject` — `&self` methods, lock-then-act, each panic-firewalled.
//!   4. `#[derive(uniffi::Enum)]` bridged twins — [`WardenVerdict`], [`WardenNetworkType`],
//!      [`WardenIpStatus`], [`WardenUniversalRule`], [`WardenAppMode`], [`WardenNetClass`] — each with the
//!      stable ordinal the Kotlin decode contract reads.
//!   5. `#[derive(uniffi::Record)]` bridged twins — [`WardenConnFacts`] (the per-conn input + the
//!      `dns_blocked` TIER-5 seam, since [`ConnFacts`] is not a UniFFI type), [`WardenDomainRule`] /
//!      [`WardenCidrRule`] / [`WardenAppRow`] / [`WardenUniversalToggles`] (the rule-set + matrix + toggle
//!      inputs), and [`WardenSnapshot`] (the dashboard one-glance state, per-tier deny attribution).
//!   6. NO callback sink (like the Centauri mirror, UNLIKE the Beast's hot `BeastMetricSink`): the
//!      Warden is verdict-event-driven, not a hot streaming metric — Kotlin pulls a snapshot when it
//!      needs one (the stats are an in-memory `u64` add, not a per-conn push).
//!
//! ## THE REWORKED-DESIGN PURE-FIREWALL VERDICT (the load-bearing semantic, `Warden-REWORKED-design.md` §2/§3)
//! The Object's [`WardenObject::verdict`] is the **PURE FIREWALL** — it takes NO blocklist parameter and
//! evaluates the deterministic 6-tier first-match-DENY cascade ([`Warden::verdict`]) over the armed
//! rule-sets + per-app matrix + universal toggles + the firewall baseline. The DNS-blocklist verdict
//! enters ONLY at TIER 5, as the [`WardenConnFacts::dns_blocked`] boolean the resolver sets on the
//! connection metadata (the narrow seam, Anti-Venom §5d) — the Warden does NOT re-query the blocklist.
//!
//! The per-verdict return [`WardenVerdict`] is the COARSE firewall pass/deny ([`Allow`](WardenVerdict::Allow)
//! / [`DenyByFirewall`](WardenVerdict::DenyByFirewall)); the FINE per-tier deny attribution
//! (universal-toggle / app / universal-rule / blocklist-seam) lives in the [`WardenSnapshot`]. The
//! [`DenyByBlocklist`](WardenVerdict::DenyByBlocklist) slot is the datapath's report for ITS separate
//! external DNS-blocklist gate — the Object's pure-firewall verdict never emits it.
//!
//! ## The rule-set / matrix / toggle layer — WIRED INTO THE ENGINE (slice-1)
//! The Object installs the armed rule-sets ([`install_domain_rules`](WardenObject::install_domain_rules) /
//! [`install_cidr_rules`](WardenObject::install_cidr_rules)), the universal rules
//! ([`set_universal_rules`](WardenObject::set_universal_rules)), the per-app matrix rows
//! ([`set_app_row`](WardenObject::set_app_row)), and the universal toggles
//! ([`set_universal_toggles`](WardenObject::set_universal_toggles)) DIRECTLY INTO the engine via its
//! granular setters, so the cascade consults them under the engine's single `&mut self` lock. The
//! snapshot reads the live engine counts. (Earlier waves HELD the rule-sets inert in a second mutex;
//! slice 1 wires them into the verdict.)
//!
//! ## NO-BREAK CONTRACT (the load-bearing law)
//! The flat `#[uniffi::export]` fn `warden_stats` + the C-ABI `torta_firewall_verdict` STAY LIVE. They
//! DELEGATE to the SAME engine fns the Object wraps ([`Warden::verdict`], [`Warden::set_fail_closed`],
//! [`Warden::stats`]). Zero firewall re-derivation. (The policy surface — `warden_configure` /
//! `warden_policy_verdict` / the `WardenPolicy` install — was REMOVED with the allow-by-default rework.)
//!
//! ## Panic firewall (fail-CLOSED, distinct from the engine's logical fail-safe)
//! Every Object method carries its OWN `catch_unwind(AssertUnwindSafe(...))` → a safe default; a panic
//! NEVER crosses the FFI boundary. The verdict's panic/poison fallback is **`Deny` (fail-CLOSED)** —
//! a SECURITY gate that crashes must NOT silently allow a connection. This is DISTINCT from the engine's
//! LOGICAL fail-safe (allow-by-default — an unruled connection allows, so connectivity never bricks).
//! A snapshot panic falls to an all-zero snapshot (honest "off").
//!
//! ## Unsafe posture
//! `#![forbid(unsafe_code)]` (module-inner, under the crate's `#![forbid(unsafe_op_in_unsafe_fn)]`,
//! `lib.rs:20`). ring-free, allocation-light (the engine + rule-sets are the existing pure-Rust types).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    cidr_match::CidrMatch, AppFirewallMode, AppMatrixRow, CidrRuleSet, ConnFacts, DomainRule,
    DomainRuleSet, IpRule, IpStatus, NetClass, NetworkType, PortSpec, ProtoSpec, UniversalRule,
    UniversalToggles, Verdict, Warden, UID_UNIVERSAL,
};

// ===========================================================================================
// Typed Error (the UniFFI-bridged failure-reason surface — R1.x.4, the full-power typed-Error lift)
// ===========================================================================================

/// THE WARDEN typed failure-reason surface (D27 — the QUARTET's `WardenError`, promised in `Cargo.toml:47`
/// but previously phantom; now the real 4th `uniffi::Error` beside `FortressError`/`CentauriError`/
/// `MaskSolverError`). It names WHY a domain rule was refused by the RFC-1123 integrity gate
/// ([`super::pattern::validate_pattern`], the poisoned-blocklist defense): the UI's add-rule pre-flight
/// ([`warden_validate_pattern`]) throws it so a user learns exactly why a rule was rejected instead of it
/// silently vanishing — the crate's error-handling standard applied to the security surface. Each variant
/// mirrors a [`super::pattern::MalformedPattern`]; the `From` below is the single mapping point.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum WardenError {
    /// The pattern is empty (all whitespace / all empty labels).
    #[error("the rule is empty")]
    Empty,
    /// The pattern exceeds the max DNS name length (253).
    #[error("the rule is too long (max 253 chars)")]
    TooLong,
    /// Fewer than two labels — a bare TLD like `com` (the over-broad nuke).
    #[error("the rule has too few labels (a bare TLD blocks everything under it)")]
    TooFewLabels,
    /// A label is empty (a `..` in the middle — malformed).
    #[error("the rule has an empty label (a `..`)")]
    EmptyLabel,
    /// A label exceeds the max label length (63).
    #[error("the rule has a label longer than 63 chars")]
    LabelTooLong,
    /// A label carries a byte outside `[a-z0-9-*]` (after canonicalization).
    #[error("the rule has an illegal character: '{ch}'")]
    BadChar {
        /// The offending character (as a string — `char` for FFI simplicity).
        ch: String,
    },
    /// A label begins or ends with a hyphen (RFC-1123).
    #[error("a label begins or ends with a hyphen")]
    LeadingOrTrailingHyphen,
    /// A label carries more than the permitted wildcards (an over-broad saturated label).
    #[error("a label has too many wildcards")]
    TooManyWildcards,
    /// Fewer than two trailing LITERAL labels (e.g. `*.com`) — the over-broad pattern the gate refuses.
    #[error("the rule is over-broad (e.g. `*.com` would block a whole TLD)")]
    OverBroad,
    /// The final label is all-numeric (an IP-shaped pseudo-TLD, never a real domain).
    #[error("the final label is all-numeric (not a real domain)")]
    NumericTld,
    /// A panic inside the bridge — the `catch_unwind` firewall caught a bug and reports it as a typed
    /// error, never an abort across the FFI boundary. Never expected (validation is panic-free); kept so
    /// the contract is total (the `MaskSolverError::Panic` precedent).
    #[error("panic in the Warden validation bridge: {reason}")]
    Panic {
        /// A short description of the caught panic.
        reason: String,
    },
}

impl From<super::pattern::MalformedPattern> for WardenError {
    /// The single mapping point from the internal integrity-gate reason to the FFI-bridged error.
    fn from(m: super::pattern::MalformedPattern) -> Self {
        use super::pattern::MalformedPattern as M;
        match m {
            M::Empty => WardenError::Empty,
            M::TooLong => WardenError::TooLong,
            M::TooFewLabels => WardenError::TooFewLabels,
            M::EmptyLabel => WardenError::EmptyLabel,
            M::LabelTooLong => WardenError::LabelTooLong,
            M::BadChar(c) => WardenError::BadChar { ch: c.to_string() },
            M::LeadingOrTrailingHyphen => WardenError::LeadingOrTrailingHyphen,
            M::TooManyWildcards => WardenError::TooManyWildcards,
            M::OverBroad => WardenError::OverBroad,
            M::NumericTld => WardenError::NumericTld,
        }
    }
}

// ===========================================================================================
// Enums (the UniFFI-bridged verdict / selector surface)
// ===========================================================================================

/// The Warden's one-glance verdict over a connection — the UniFFI-bridged COARSE firewall pass/deny.
/// `code()` is the STABLE ordinal the dashboard reads (`Allow=0 · DenyByFirewall=1 · DenyByBlocklist=2`).
///
/// The Object's [`WardenObject::verdict`] is the PURE FIREWALL cascade, so it ONLY ever emits [`Allow`] or
/// [`DenyByFirewall`] (the Warden IS the firewall; every cascade deny — including the TIER-5 `dns_blocked`
/// seam — is a firewall deny at the per-verdict grain). The FINE per-tier attribution is in the
/// [`WardenSnapshot`]. [`DenyByBlocklist`] is the REPORT slot the DATAPATH populates for ITS separate
/// external DNS-blocklist gate (the Object's pure-firewall verdict never emits it).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenVerdict {
    /// No cascade tier denied — the connection passes the firewall gate.
    Allow = 0,
    /// A cascade tier denied — the firewall refused the connection. The per-tier breakdown is in the
    /// snapshot; the per-verdict return is coarse.
    DenyByFirewall = 1,
    /// The datapath's SEPARATE external DNS-blocklist gate denied — the report slot the caller sets. The
    /// Object's pure-firewall verdict never emits this.
    DenyByBlocklist = 2,
}

impl WardenVerdict {
    /// The stable ordinal (the dashboard decode contract). `#[repr(i32)]` so this is a zero-cost cast;
    /// kept as a named fn so the ordinal contract is documented + asserted in tests.
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Map the internal [`Verdict`] to the bridged verdict. A [`Verdict::Deny`] from the Object's path maps
    /// to [`WardenVerdict::DenyByFirewall`] — the Warden cascade IS the firewall, so any cascade deny is a
    /// firewall deny at this coarse grain. [`WardenVerdict::DenyByBlocklist`] is the datapath's slot.
    fn from_internal(v: Verdict) -> Self {
        match v {
            Verdict::Allow => WardenVerdict::Allow,
            Verdict::Deny => WardenVerdict::DenyByFirewall,
        }
    }
}

/// The active network type — the UniFFI-bridged twin of the internal [`NetworkType`] (the firewall-baseline
/// allow-set selector). Declaration order mirrors the internal enum (`Lan=0 · Wifi=1 · Gsm=2 · Roaming=3 ·
/// Vpn=4`); the live datapath sets [`Lan`](WardenNetworkType::Lan) when the destination is LAN-range.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenNetworkType {
    /// A LAN-range destination — the orthogonal axis, decided by the LAN allow-set.
    Lan = 0,
    /// Wi-Fi (also covers Ethernet, which collapses to the Wi-Fi set).
    Wifi = 1,
    /// Cellular / mobile data (non-roaming).
    Gsm = 2,
    /// Cellular while roaming.
    Roaming = 3,
    /// The VPN-tunnel-bypass axis.
    Vpn = 4,
}

impl WardenNetworkType {
    /// The stable ordinal (asserted in tests against the internal declaration order).
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Map to the internal [`NetworkType`] for the verdict compose.
    fn to_internal(self) -> NetworkType {
        match self {
            WardenNetworkType::Lan => NetworkType::Lan,
            WardenNetworkType::Wifi => NetworkType::Wifi,
            WardenNetworkType::Gsm => NetworkType::Gsm,
            WardenNetworkType::Roaming => NetworkType::Roaming,
            WardenNetworkType::Vpn => NetworkType::Vpn,
        }
    }
}

/// The status of a CIDR rule — the UniFFI-bridged twin of the internal [`IpStatus`] (BLOCK-only after TRUST
/// is trashed; [`Bypass`](WardenIpStatus::Bypass) is "skip the universal tier", RULE2C, NOT trust).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenIpStatus {
    /// Block matching traffic.
    Block = 0,
    /// Bypass the universal tier for matching traffic (RULE2C IP-wildcard bypass — NOT trust).
    Bypass = 1,
    /// No rule (the row exists but is inert).
    None = 2,
}

impl WardenIpStatus {
    fn to_internal(self) -> IpStatus {
        match self {
            WardenIpStatus::Block => IpStatus::Block,
            WardenIpStatus::Bypass => IpStatus::Bypass,
            WardenIpStatus::None => IpStatus::None,
        }
    }

    /// The inverse of [`to_internal`](Self::to_internal) — map a held engine [`IpStatus`] back across the
    /// FFI for the settings-pane rule LIST ([`WardenObject::cidr_rules`]).
    fn from_internal(v: IpStatus) -> Self {
        match v {
            IpStatus::Block => WardenIpStatus::Block,
            IpStatus::Bypass => WardenIpStatus::Bypass,
            IpStatus::None => WardenIpStatus::None,
        }
    }
}

/// A universal firewall rule — the UniFFI-bridged twin of the internal [`UniversalRule`] (the RethinkDNS
/// RULE1B/F/3/4/6/7/10/11 toggles + the global-CIDR/global-domain markers). BLOCK-only by REWORKED law;
/// every variant is a deny toggle, there is NO trust variant.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenUniversalRule {
    /// RULE1B — block apps not yet seen (the new-app-default).
    BlockNewApps = 0,
    /// RULE1F — block all metered (cellular/roaming) traffic.
    BlockMetered = 1,
    /// RULE11 — universal lockdown (block everything except the allow-list).
    Lockdown = 2,
    /// RULE3 — device-lock (block on screen-off).
    DeviceLock = 3,
    /// RULE4 — block background-data (foreground-only).
    BlockBackground = 4,
    /// RULE6 — block UDP-NTP (port 123 / UDP).
    BlockUdpNtp = 5,
    /// RULE10 — block HTTP (port 80).
    BlockHttp = 6,
    /// RULE7 — block DNS bypass (a query trying to skip the resolver).
    BlockDnsBypass = 7,
    /// RULE2D — a universal CIDR block (the global-IP table marker).
    BlockUniversalCidr = 8,
    /// RULE2H — a universal domain block (the global-domain table marker).
    BlockUniversalDomain = 9,
}

impl WardenUniversalRule {
    /// Map to the internal [`UniversalRule`] (construction inside the defining crate is allowed despite the
    /// internal enum's `#[non_exhaustive]`, which only restricts FOREIGN crates).
    fn to_internal(self) -> UniversalRule {
        match self {
            WardenUniversalRule::BlockNewApps => UniversalRule::BlockNewApps,
            WardenUniversalRule::BlockMetered => UniversalRule::BlockMetered,
            WardenUniversalRule::Lockdown => UniversalRule::Lockdown,
            WardenUniversalRule::DeviceLock => UniversalRule::DeviceLock,
            WardenUniversalRule::BlockBackground => UniversalRule::BlockBackground,
            WardenUniversalRule::BlockUdpNtp => UniversalRule::BlockUdpNtp,
            WardenUniversalRule::BlockHttp => UniversalRule::BlockHttp,
            WardenUniversalRule::BlockDnsBypass => UniversalRule::BlockDnsBypass,
            WardenUniversalRule::BlockUniversalCidr => UniversalRule::BlockUniversalCidr,
            WardenUniversalRule::BlockUniversalDomain => UniversalRule::BlockUniversalDomain,
        }
    }
}

/// The per-app firewall mode — the UniFFI-bridged twin of the internal [`AppFirewallMode`] (TIER 3 matrix
/// mode). Additive-block-only: `None | Isolate | Untracked` are the DENY-shaping modes; the bypass arms
/// (`BypassUniversal` / `BypassDnsFirewall`) SKIP a tier, `Exclude` is handled by the datapath.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenAppMode {
    /// RULE8 — bypass the universal tier (TIER 4) for this app (still subject to per-app rules + TIER 5).
    BypassUniversal = 0,
    /// The app is excluded from the VPN entirely (datapath concern; recognized for completeness).
    Exclude = 1,
    /// RULE1G — isolate: the app may only talk the DNS resolver + the LAN.
    Isolate = 2,
    /// No special mode — the app is subject to the baseline + tiers.
    None = 3,
    /// RULE5 — untracked (never seen by the firewall). Subject to the new-app/unknown universal toggles.
    Untracked = 4,
    /// RULE1H — bypass the DNS firewall (TIER 5 `dns_blocked` seam) for this app.
    BypassDnsFirewall = 5,
}

impl WardenAppMode {
    fn to_internal(self) -> AppFirewallMode {
        match self {
            WardenAppMode::BypassUniversal => AppFirewallMode::BypassUniversal,
            WardenAppMode::Exclude => AppFirewallMode::Exclude,
            WardenAppMode::Isolate => AppFirewallMode::Isolate,
            WardenAppMode::None => AppFirewallMode::None,
            WardenAppMode::Untracked => AppFirewallMode::Untracked,
            WardenAppMode::BypassDnsFirewall => AppFirewallMode::BypassDnsFirewall,
        }
    }

    /// The exact inverse of [`to_internal`](Self::to_internal) — the matrix READ direction
    /// ([`WardenObject::app_rows`], the per-app firewall UI list).
    fn from_internal(mode: AppFirewallMode) -> Self {
        match mode {
            AppFirewallMode::BypassUniversal => WardenAppMode::BypassUniversal,
            AppFirewallMode::Exclude => WardenAppMode::Exclude,
            AppFirewallMode::Isolate => WardenAppMode::Isolate,
            AppFirewallMode::None => WardenAppMode::None,
            AppFirewallMode::Untracked => WardenAppMode::Untracked,
            AppFirewallMode::BypassDnsFirewall => WardenAppMode::BypassDnsFirewall,
        }
    }
}

/// The per-network meteredness block — the UniFFI-bridged twin of the internal [`NetClass`]
/// (`ConnectionStatus`). `Allow` = no meteredness block; the others block on the matching network class.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WardenNetClass {
    /// Block on BOTH metered (cellular) AND unmetered (Wi-Fi) — the block-all meteredness.
    Both = 0,
    /// Block on unmetered (Wi-Fi/VPN) only.
    Unmetered = 1,
    /// Block on metered (cellular) only.
    Metered = 2,
    /// No meteredness block.
    Allow = 3,
}

impl WardenNetClass {
    fn to_internal(self) -> NetClass {
        match self {
            WardenNetClass::Both => NetClass::Both,
            WardenNetClass::Unmetered => NetClass::Unmetered,
            WardenNetClass::Metered => NetClass::Metered,
            WardenNetClass::Allow => NetClass::Allow,
        }
    }

    /// The exact inverse of [`to_internal`](Self::to_internal) — the matrix READ direction
    /// ([`WardenObject::app_rows`], the per-app firewall UI list).
    fn from_internal(class: NetClass) -> Self {
        match class {
            NetClass::Both => WardenNetClass::Both,
            NetClass::Unmetered => WardenNetClass::Unmetered,
            NetClass::Metered => WardenNetClass::Metered,
            NetClass::Allow => WardenNetClass::Allow,
        }
    }
}

// ===========================================================================================
// Records (the per-conn input + the rule-set / matrix / toggle inputs + the dashboard snapshot)
// ===========================================================================================

/// The facts the datapath hands the verdict engine for ONE connection — the UniFFI-bridged twin of the
/// internal [`ConnFacts`] (which is not a UniFFI type: its `daddr` is an [`IpAddr`]). `daddr` crosses the
/// FFI as a string (e.g. `"93.184.216.34"`); [`qname`](WardenConnFacts::qname) is `Some` only for a
/// DNS-bearing connection.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenConnFacts {
    /// The owning app's UID (Android UID; maps to Kotlin `UInt`).
    pub uid: u32,
    /// The destination IP as a string (parsed to an [`IpAddr`]; an unparseable value fails the verdict
    /// CLOSED — see [`WardenObject::verdict`]). Consumed by the per-app/universal CIDR tiers.
    pub daddr: String,
    /// The destination port.
    pub dport: u16,
    /// The IP protocol number (6 = TCP, 17 = UDP).
    pub proto: u8,
    /// The queried domain for a DNS-bearing connection; `null` otherwise.
    pub qname: Option<String>,
    /// The resolved active network type (the firewall-baseline set selector + the meteredness axis).
    pub net: WardenNetworkType,
    /// TIER 5 seam — the DNS resolver set this `true` when ITS blocklist denied the resolved name+addr.
    /// The Warden trusts the flag; it does NOT re-query the blocklist. Default `false` (the resolver
    /// abstained or this is a non-DNS conn). Skipped for [`WardenAppMode::BypassDnsFirewall`].
    pub dns_blocked: bool,
}

impl WardenConnFacts {
    /// Build the internal [`ConnFacts`], or `None` if `daddr` is not a parseable IP (a malformed fact ⇒
    /// the caller fails the verdict CLOSED). Pure; no IO.
    fn to_internal(&self) -> Option<ConnFacts> {
        let daddr: IpAddr = self.daddr.parse().ok()?;
        Some(ConnFacts {
            uid: self.uid,
            daddr,
            dport: self.dport,
            proto: self.proto,
            qname: self.qname.clone(),
            net: self.net.to_internal(),
            dns_blocked: self.dns_blocked,
        })
    }
}

/// A BLOCK domain rule — the UniFFI-bridged twin of the internal [`DomainRule`]. `uid = 0`
/// ([`crate::warden::UID_UNIVERSAL`]) is the universal-domain tier (TIER 4); any other uid is per-app (TIER 3).
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenDomainRule {
    /// The domain apex (canonicalized on insert).
    pub domain: String,
    /// Owning app UID; `0` = the universal tier.
    pub uid: u32,
    /// `true` → apex + every subdomain (the `*.domain` form).
    pub wildcard: bool,
}

/// A BLOCK/Bypass CIDR rule — the UniFFI-bridged twin of the internal [`IpRule`]. `port = null` ⇒ any
/// port; `proto = null` ⇒ any protocol (else the IP protocol byte: 6 = TCP, 17 = UDP, other = that
/// number). `uid = 0` is the universal-IP tier.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenCidrRule {
    /// Owning app UID; `0` = the universal tier.
    pub uid: u32,
    /// Host-order IPv4 network address.
    pub net: u32,
    /// Prefix length `0..=32` (`0` = the IP-wildcard form, matches everything).
    pub prefix: u8,
    /// Exact destination port, or `null` for any.
    pub port: Option<u16>,
    /// The IP protocol byte (6 = TCP, 17 = UDP, other = that number), or `null` for any.
    pub proto: Option<u8>,
    /// Block / Bypass / None.
    pub status: WardenIpStatus,
}

impl WardenCidrRule {
    /// Build the internal [`IpRule`]. `proto` maps a byte to the richest [`ProtoSpec`] with identical
    /// `accepts` semantics (6 → Tcp, 17 → Udp, other → Other) so the matcher behaves identically.
    fn to_internal(&self) -> IpRule {
        IpRule {
            uid: self.uid,
            // The WIRE form is v4-only today (net: u32); the ENGINE is family-aware (A3). The v6
            // wire form (a parsed-string CIDR) is the A3b follow-up — it widens this record.
            cidr: CidrMatch::V4 {
                net: self.net,
                prefix: self.prefix,
            },
            port: match self.port {
                None => PortSpec::Any,
                Some(p) => PortSpec::Exact(p),
            },
            proto: match self.proto {
                None => ProtoSpec::Any,
                Some(6) => ProtoSpec::Tcp,
                Some(17) => ProtoSpec::Udp,
                Some(p) => ProtoSpec::Other(p),
            },
            status: self.status.to_internal(),
        }
    }

    /// The inverse of [`to_internal`](Self::to_internal) — map a held engine [`IpRule`] back across the
    /// FFI for the settings-pane rule LIST ([`WardenObject::cidr_rules`]). The wire net is a host-order v4
    /// `u32`, so a v6 rule (the A3 family-aware engine can hold one) cannot round-trip and yields `None`
    /// (skipped, never silently truncated to a wrong v4 net). `PortSpec::Any`/`ProtoSpec::Any` collapse to
    /// `null`; a concrete [`ProtoSpec`] maps back to its IP protocol byte.
    fn from_internal(rule: IpRule) -> Option<Self> {
        let (net, prefix) = match rule.cidr {
            CidrMatch::V4 { net, prefix } => (net, prefix),
            CidrMatch::V6 { .. } => return None,
        };
        Some(Self {
            uid: rule.uid,
            net,
            prefix,
            port: match rule.port {
                PortSpec::Any => None,
                PortSpec::Exact(p) => Some(p),
            },
            proto: match rule.proto {
                ProtoSpec::Any => None,
                ProtoSpec::Tcp => Some(6),
                ProtoSpec::Udp => Some(17),
                ProtoSpec::Other(p) => Some(p),
            },
            status: WardenIpStatus::from_internal(rule.status),
        })
    }
}

/// W-C (#86) — format a held [`IpRule`]'s CIDR as its canonical wire TEXT, v4 AND v6. The v6-capable
/// sibling of the Kotlin `netToDotted` (which is v4-`u32`-only): a v4 rule renders dotted-quad via
/// [`Ipv4Addr`], a v6 rule the compressed hextet form via [`Ipv6Addr`] — so a v6 host block armed by
/// [`WardenObject::block_ip`] finally has a printable form. The proto/port suffix mirrors the pane's
/// existing row (`" tcp"`/`" udp"`/`" proto<N>"` then `":<port>"`), so the rendered line is identical
/// whichever family it is. Bare `Any`/`Any` = no suffix (a blanket host block).
fn format_cidr_rule(rule: &IpRule) -> String {
    let base = match rule.cidr {
        CidrMatch::V4 { net, prefix } => format!("{}/{}", Ipv4Addr::from(net), prefix),
        CidrMatch::V6 { net, prefix } => format!("{}/{}", Ipv6Addr::from(net), prefix),
    };
    let proto = match rule.proto {
        ProtoSpec::Any => String::new(),
        ProtoSpec::Tcp => " tcp".to_string(),
        ProtoSpec::Udp => " udp".to_string(),
        ProtoSpec::Other(p) => format!(" proto{}", p),
    };
    let port = match rule.port {
        PortSpec::Any => String::new(),
        PortSpec::Exact(p) => format!(":{}", p),
    };
    format!("{}{}{}", base, proto, port)
}

/// One per-app matrix row — the UniFFI-bridged twin of the internal [`AppMatrixRow`] (TIER 3 per-app
/// verdict tier). The per-app USER intent: the firewall mode + the meteredness block + the temp-allow
/// expiry. The datapath/UI authors these; the cascade consults them.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenAppRow {
    /// The owning app's UID. Shared-uid apps collapse to one row.
    pub uid: u32,
    /// The per-app firewall mode.
    pub mode: WardenAppMode,
    /// The meteredness block (orthogonal to `mode`).
    pub meteredness: WardenNetClass,
    /// Temp-allow expiry (epoch ms). `0` = disabled. While non-zero, the app's per-app denies are paused
    /// (RULE19). The caller (UI/datapath) clears this to `0` once the wall-clock passes the expiry; the
    /// engine does NOT reach for a clock on the hot path.
    pub temp_allow_until: u64,
}

impl WardenAppRow {
    fn to_internal(&self) -> AppMatrixRow {
        AppMatrixRow {
            uid: self.uid,
            mode: self.mode.to_internal(),
            meteredness: self.meteredness.to_internal(),
            temp_allow_until: self.temp_allow_until,
        }
    }

    /// The exact inverse of [`to_internal`](Self::to_internal) — maps a held engine matrix row back
    /// across the FFI for the per-app firewall UI read ([`WardenObject::app_rows`]).
    fn from_internal(row: &AppMatrixRow) -> Self {
        Self {
            uid: row.uid,
            mode: WardenAppMode::from_internal(row.mode),
            meteredness: WardenNetClass::from_internal(row.meteredness),
            temp_allow_until: row.temp_allow_until,
        }
    }
}

/// The 9 universal DENY toggles — the UniFFI-bridged twin of the internal [`UniversalToggles`] (TIER 2,
/// the `|||` settings section). Each is an INDEPENDENT global DENY switch; a toggle fires only when BOTH
/// its bit is set AND its matching [`WardenUniversalRule`] is armed (defense-in-depth — a stale settings
/// write cannot deny alone). All default `false` (the inert allow-all baseline).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, uniffi::Record)]
pub struct WardenUniversalToggles {
    /// RULE1B — block apps not yet seen (gated by `WardenAppMode::Untracked`).
    #[uniffi(default = false)]
    pub block_new_apps: bool,
    /// RethinkDNS step 3 — block connections from unknown/untracked UIDs.
    #[uniffi(default = false)]
    pub block_unknown_conns: bool,
    /// RULE1F — block all metered (cellular/roaming) traffic.
    #[uniffi(default = false)]
    pub block_metered: bool,
    /// RULE11 — universal lockdown.
    #[uniffi(default = false)]
    pub lockdown: bool,
    /// RULE3 — device-lock (block on screen-off).
    #[uniffi(default = false)]
    pub device_lock: bool,
    /// RULE4 — block background-data (foreground-only).
    #[uniffi(default = false)]
    pub block_background: bool,
    /// RULE6 — block UDP-NTP (port 123 / UDP).
    #[uniffi(default = false)]
    pub block_udp_ntp: bool,
    /// RULE10 — block HTTP (port 80).
    #[uniffi(default = false)]
    pub block_http: bool,
    /// RULE7 — block DNS bypass (a query trying to skip the resolver).
    #[uniffi(default = false)]
    pub block_dns_bypass: bool,
}

impl WardenUniversalToggles {
    fn to_internal(self) -> UniversalToggles {
        UniversalToggles {
            block_new_apps: self.block_new_apps,
            block_unknown_conns: self.block_unknown_conns,
            block_metered: self.block_metered,
            lockdown: self.lockdown,
            device_lock: self.device_lock,
            block_background: self.block_background,
            block_udp_ntp: self.block_udp_ntp,
            block_http: self.block_http,
            block_dns_bypass: self.block_dns_bypass,
        }
    }

    fn from_internal(t: UniversalToggles) -> Self {
        Self {
            block_new_apps: t.block_new_apps,
            block_unknown_conns: t.block_unknown_conns,
            block_metered: t.block_metered,
            lockdown: t.lockdown,
            device_lock: t.device_lock,
            block_background: t.block_background,
            block_udp_ntp: t.block_udp_ntp,
            block_http: t.block_http,
            block_dns_bypass: t.block_dns_bypass,
        }
    }
}

/// One live Warden snapshot — everything the dashboard renders about the verdict tallies (per-tier deny
/// attribution), the policy state, and the armed rule-set / matrix counts. Kotlin pulls this via
/// [`WardenObject::snapshot`]; pure data, all fields `pub`, flat primitives (a dashboard
/// one-glance Record). Every number is a REAL read of the live engine, never faked.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenSnapshot {
    /// Connections the verdict ALLOWED (no cascade tier denied).
    pub allow: i64,
    /// Connections the verdict DENIED (at least one tier fired).
    pub deny: i64,
    /// Of the denies, those attributed to TIER 2 — the universal toggles (the `|||` settings section).
    pub deny_by_universal_toggle: i64,
    /// Of the denies, those attributed to TIER 3 — the per-app matrix (mode/meteredness/temp-allow + the
    /// per-app domain/CIDR rules).
    pub deny_by_app: i64,
    /// Of the denies, those attributed to TIER 4 — the universal domain/CIDR rule-set (skipped for
    /// `BypassUniversal`).
    pub deny_by_universal_rule: i64,
    /// Of the denies, those attributed to TIER 5 — the `dns_blocked` resolver seam (skipped for
    /// `BypassDnsFirewall`). Name kept for dashboard label continuity; semantics = TIER 5.
    pub deny_by_blocklist: i64,
    /// Is the verdict engine armed? Always `true` for a constructed Warden (allow-by-default; the legacy
    /// policy-load was removed). Kept in the Record for dashboard-surface continuity.
    pub policy_loaded: bool,
    /// The fail-CLOSED posture bit (Nerd surface). Inert in the additive-block model — no verdict effect;
    /// kept as the snapshot-surfaced posture flag.
    pub fail_closed: bool,
    /// Live entries in the bounded per-connection decision cache (the RAM hot tier).
    pub cache_entries: i64,
    /// Armed BLOCK domain rules (per-app + universal), consulted by the cascade.
    pub domain_rules: i64,
    /// Armed CIDR rules (per-app + universal), consulted by the cascade.
    pub cidr_rules: i64,
    /// Armed universal rules (the RULE toggles driving TIER 2).
    pub universal_rules: i64,
    /// Held per-app matrix rows (TIER 3).
    pub app_rows: i64,
}

/// ONE rejected domain rule — WHICH rule the RFC-1123 integrity gate refused and WHY (D27). The reason is
/// the human-legible [`WardenError`] `Display` string (a `uniffi::Error` cannot be a `uniffi::Record`
/// field, so the Record carries the rendered text; the throwing [`warden_validate_pattern`] carries the
/// typed error). Lets the add-rule UI render "3 of 100 rules rejected: … because …" instead of silently
/// dropping them (the crate's error-honesty standard on a security surface).
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenRejectedRule {
    /// The offending rule text, exactly as authored.
    pub rule: String,
    /// The human-legible rejection reason ([`WardenError`] `Display`).
    pub reason: String,
}

/// The result of [`WardenObject::install_domain_rules`] (D27) — the typed twin of the former bare `i64`.
/// Carries the accepted COUNT plus a BOUNDED list of rejected rules (the integrity-gate refusals), so a
/// user pasting 100 rules learns exactly which few died and why instead of "97 armed, 3 vanished". The
/// `rejected` list is capped ([`MAX_REJECTED_REPORTED`]) so a hostile all-malformed paste can never balloon
/// the FFI payload.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WardenInstallReport {
    /// The count of rules that PASSED the gate and armed (trie terminals + validated globs).
    pub accepted: i64,
    /// The rejected rules (rule + reason), bounded to [`MAX_REJECTED_REPORTED`]; a truncated tail is
    /// reflected by [`rejected_total`](Self::rejected_total) exceeding `rejected.len()`.
    pub rejected: Vec<WardenRejectedRule>,
    /// The TOTAL number rejected (may exceed `rejected.len()` when the reported list was capped).
    pub rejected_total: i64,
}

/// The cap on the number of individually-reported rejected rules in a [`WardenInstallReport`] — a hostile
/// all-malformed paste can never grow the FFI payload past this (the `rejected_total` still reports the
/// true count).
const MAX_REJECTED_REPORTED: usize = 64;

// ===========================================================================================
// THE WARDEN OBJECT
// ===========================================================================================

/// THE WARDEN — the stateful pure-firewall pillar. Kotlin constructs it ONCE at boot, holds the `Arc`
/// handle, then (allow-by-default — no policy install; the legacy `WardenPolicy` was removed):
///   - arms the rule-sets via [`install_domain_rules`](WardenObject::install_domain_rules) /
///     [`install_cidr_rules`](WardenObject::install_cidr_rules) /
///     [`set_universal_rules`](WardenObject::set_universal_rules),
///   - arms the per-app matrix via [`set_app_row`](WardenObject::set_app_row) /
///     [`remove_app_row`](WardenObject::remove_app_row),
///   - arms the universal toggles via [`set_universal_toggles`](WardenObject::set_universal_toggles),
///   - sets the fail-closed posture via [`WardenObject::set_fail_closed`],
///   - rules on each connection via [`WardenObject::verdict`] (PURE FIREWALL cascade),
///   - pulls a [`WardenSnapshot`] for the dashboard via [`WardenObject::snapshot`].
///
/// Interior state is ONE `Mutex<Warden>` (std) — `#![forbid(unsafe_code)]` honored. The engine encapsulates
/// the cache + stats + fail_closed + the armed rule-sets + matrix + toggles (allow-by-default — no policy),
/// all behind the single lock its `&mut self` mutators already require. Each public method panic-firewalls
/// its body — a bug returns a safe default (the verdict fails CLOSED), never aborts the app.
#[derive(uniffi::Object)]
pub struct WardenObject {
    /// The verdict engine — the single owner of the cache + stats + fail_closed + the armed rule-sets +
    /// matrix + toggles. Behind ONE `Mutex` since its mutators take `&mut self`.
    engine: Mutex<Warden>,
    /// Epoch-ms of the last RULE19 verdict-edge TempAllow sweep (0 = never). The rate-limiter behind
    /// [`temp_allow_sweep_due`](Self::temp_allow_sweep_due) — PER-OBJECT (a test's fresh instance
    /// always owns its first sweep), FFI-invisible (UniFFI Objects are opaque handles; no bindgen).
    last_temp_sweep_ms: AtomicU64,
}

/// RULE19 verdict-edge sweep cadence. The tap-pause TTL is an HOUR (the Kotlin granter's
/// `WARDEN_PAUSE_TTL_MS`); a ≤60 s expiry lag is invisible to the user, and the sweep itself is
/// O(rows) over a handful of exception rows — negligible beside the verdict's own lock + cascade.
const TEMP_ALLOW_SWEEP_INTERVAL_MS: u64 = 60_000;

#[uniffi::export]
impl WardenObject {
    /// Construct the Warden in the cold ALLOW-BY-DEFAULT baseline. UniFFI Object ctors MUST return
    /// `Arc<Self>`. The engine is an empty [`Warden`] (no rules / matrix / toggles → allow-all, NEVER
    /// bricks before any rule arms; the legacy `WardenPolicy` baseline was removed). IO-free, so infallible
    /// (a cold, IO-free constructor). Arm the rule-sets / matrix / toggles via the
    /// methods below.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            engine: Mutex::new(Warden::new()),
            last_temp_sweep_ms: AtomicU64::new(0),
        })
    }

    /// THE VERDICT — the PURE FIREWALL cascade (REWORKED §2). Rules on ONE connection over the armed
    /// rule-sets + matrix + toggles + the firewall baseline; the DNS-blocklist enters ONLY at TIER 5 via
    /// [`WardenConnFacts::dns_blocked`]. Delegates to the EXISTING [`Warden::verdict`] (NO blocklist param)
    /// and maps the internal [`Verdict`] to the bridged [`WardenVerdict`] (a deny is
    /// [`WardenVerdict::DenyByFirewall`] at the coarse grain; the per-tier breakdown is in the snapshot).
    ///
    /// FAIL-CLOSED on a fault: a malformed `daddr`, a poisoned engine lock, or a panic ⇒ `Deny` (a
    /// security gate must not silently allow). This is the PANIC path — DISTINCT from the engine's LOGICAL
    /// fail-safe (allow-by-default — an unruled conn allows inside `engine.verdict`).
    ///
    /// RULE19 EDGE SWEEP: at most once per [`TEMP_ALLOW_SWEEP_INTERVAL_MS`], a due verdict first clears
    /// every LAPSED temp-allow pause (same lock hold — the very verdict that trips the sweep already sees
    /// the resumed denies). This closes the runtime half of the TempAllow TTL: the boot edge sweeps once
    /// per process; the verdict edge sweeps the pauses GRANTED mid-session (the 1 h tap-pause), so a lapsed
    /// pause can never shield an app until the next reboot.
    pub fn verdict(&self, conn: WardenConnFacts) -> WardenVerdict {
        let sweep_now = self.temp_allow_sweep_due();
        let v = catch_unwind(AssertUnwindSafe(|| {
            let internal = match conn.to_internal() {
                Some(c) => c,
                // A malformed connection fact ⇒ fail CLOSED (cannot evaluate ⇒ refuse).
                None => return Verdict::Deny,
            };
            match self.engine.lock() {
                Ok(mut engine) => {
                    if let Some(now_ms) = sweep_now {
                        let _ = engine.expire_temp_allows(now_ms);
                    }
                    engine.verdict(&internal)
                }
                // A poisoned lock (impossible — verdict is panic-free arithmetic) ⇒ fail CLOSED.
                Err(_) => Verdict::Deny,
            }
        }))
        // A panic in the gate ⇒ fail CLOSED (a bug must not leak).
        .unwrap_or(Verdict::Deny);
        WardenVerdict::from_internal(v)
    }

    /// Set the fail-CLOSED posture bit (the Nerd / paranoid knob). Inert in the additive-block model (no
    /// verdict effect — the policy-absent deny path was removed); kept as the snapshot-surfaced posture
    /// flag. Delegates to [`Warden::set_fail_closed`] (which flushes the cache on the posture flip).
    /// Panic-firewalled to a no-op.
    pub fn set_fail_closed(&self, fail_closed: bool) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut engine) = self.engine.lock() {
                engine.set_fail_closed(fail_closed);
            }
        }));
    }

    /// Install (REPLACE) the BLOCK domain rule-set from a fresh authoring, ARMING it in the engine (TIER 3
    /// per-app + TIER 4 universal, by each rule's `uid`). Builds a new [`DomainRuleSet`] from `rules`,
    /// finalizes it (canonical + de-duplicated), swaps it into the engine (cache-flushing), and returns a
    /// [`WardenInstallReport`] (D27 — the typed twin of the former bare `i64`): the accepted COUNT PLUS the
    /// BOUNDED list of rejected rules with WHY each died (the RFC-1123 integrity gate no longer drops the
    /// poison SILENTLY). Panic-firewalled → an empty report (`accepted = 0`, no rejections).
    pub fn install_domain_rules(&self, rules: Vec<WardenDomainRule>) -> WardenInstallReport {
        catch_unwind(AssertUnwindSafe(|| {
            let mut set = DomainRuleSet::new();
            let mut globs: Vec<super::pattern::DomainPattern> = Vec::new();
            let mut rejected: Vec<WardenRejectedRule> = Vec::new();
            let mut rejected_total: i64 = 0;
            for r in &rules {
                // SLICE 3 — THE RFC-1123 INTEGRITY GATE (the poisoned-blocklist defense). Every incoming
                // rule is validated BEFORE it arms: an over-broad (`*.com`) / malformed (`com`, bad
                // charset, 64-char label) rule is REJECTED here — not counted, never entering the verdict.
                // D27: a rejection is now REPORTED (bounded) instead of a silent `continue`. A validated
                // `*`-bearing rule becomes a live glob (the dnsmasq per-label glob); a plain domain flows
                // to the reversed-label trie.
                let pattern = match super::pattern::validate_pattern(&r.domain) {
                    Ok(p) => p,
                    Err(m) => {
                        rejected_total += 1;
                        if rejected.len() < MAX_REJECTED_REPORTED {
                            rejected.push(WardenRejectedRule {
                                rule: r.domain.clone(),
                                reason: WardenError::from(m).to_string(),
                            });
                        }
                        continue;
                    }
                };
                if pattern.has_any_wildcard() {
                    globs.push(pattern);
                } else {
                    set.insert(DomainRule {
                        domain: r.domain.as_str().into(),
                        uid: r.uid,
                        wildcard: r.wildcard,
                    });
                }
            }
            set.finalize();
            // The accepted-rule count = canonical trie terminals + validated glob patterns (rejected
            // rules are excluded — the count reflects what actually armed).
            let accepted = (set.len() + globs.len()) as i64;
            match self.engine.lock() {
                Ok(mut engine) => {
                    engine.set_domain_rules(set);
                    engine.set_domain_globs(globs);
                    WardenInstallReport {
                        accepted,
                        rejected,
                        rejected_total,
                    }
                }
                // A poisoned engine lock ⇒ nothing armed; report zero accepted (the rejections computed
                // above are moot since the set never installed).
                Err(_) => WardenInstallReport {
                    accepted: 0,
                    rejected: Vec::new(),
                    rejected_total: 0,
                },
            }
        }))
        .unwrap_or(WardenInstallReport {
            accepted: 0,
            rejected: Vec::new(),
            rejected_total: 0,
        })
    }

    /// Install (REPLACE) the CIDR rule-set from a fresh authoring, ARMING it in the engine. Builds a new
    /// [`CidrRuleSet`] from `rules`, finalizes it (de-duplicated), swaps it into the engine (cache-flushing),
    /// and returns the rule COUNT. Panic-firewalled → `0`.
    pub fn install_cidr_rules(&self, rules: Vec<WardenCidrRule>) -> i64 {
        catch_unwind(AssertUnwindSafe(|| {
            let mut set = CidrRuleSet::new();
            for r in &rules {
                set.insert(r.to_internal());
            }
            set.finalize();
            let n = set.len() as i64;
            match self.engine.lock() {
                Ok(mut engine) => {
                    engine.set_cidr_rules(set);
                    n
                }
                Err(_) => 0,
            }
        }))
        .unwrap_or(0)
    }

    /// Set (REPLACE) the armed universal rule set, ARMING TIER 2 (alongside the toggles). Returns the COUNT
    /// armed. Panic-firewalled → `0`.
    pub fn set_universal_rules(&self, rules: Vec<WardenUniversalRule>) -> i64 {
        catch_unwind(AssertUnwindSafe(|| {
            let mapped: Vec<UniversalRule> = rules.iter().map(|r| r.to_internal()).collect();
            let n = mapped.len() as i64;
            match self.engine.lock() {
                Ok(mut engine) => {
                    engine.set_universal_rules(mapped);
                    n
                }
                Err(_) => 0,
            }
        }))
        .unwrap_or(0)
    }

    /// W-D (#79) — set (REPLACE) the GEO-FAMILY block set: the ISO-3166 alpha-2 country codes the user
    /// blocks wholesale (the inspector's "block this country" ladder rung). Each code is lowercased +
    /// gated to two ASCII letters by the engine; garbage is dropped. Returns the COUNT armed. The block
    /// is best-effort by the geoip caveat law (a mislabeled IP is the user's known trade-off), but it is
    /// USER-EXPLICIT policy, so it legitimately drives a TIER-4 deny. Panic-firewalled → `0`.
    pub fn set_geo_blocks(&self, codes: Vec<String>) -> i64 {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(mut engine) => {
                engine.set_geo_blocks(&codes);
                engine.geo_blocks().len() as i64
            }
            Err(_) => 0,
        }))
        .unwrap_or(0)
    }

    /// W-D (#79) — the armed GEO-family block codes (lowercase, sorted ASC), so the inspector renders the
    /// current country-block posture. Pure read; panic-firewalled / poisoned lock → an empty list.
    pub fn geo_blocks(&self) -> Vec<String> {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => engine.geo_blocks(),
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// W-D (#79) — BLOCK an IP or CIDR family from the inspector's block-ladder, ADDITIVELY (the armed
    /// rule-set is not clobbered). `cidr` is a family-aware CIDR string: `"8.8.8.8"` = a `/32` single
    /// host, `"8.8.8.0/24"` = a whole neighbourhood, `"2001:db8::/48"` = a v6 family — the v4-only
    /// `install_cidr_rules` wire (`net: u32`) could never carry a v6 host block; this seam can. `uid = 0`
    /// ([`UID_UNIVERSAL`]) blocks it for EVERY app; a real uid scopes it to one app (the per-app rung).
    /// Any port, any proto (a blanket host block). Returns `true` if the CIDR parsed + the rule armed;
    /// `false` on a malformed CIDR (abstain — never a false deny) or a poisoned lock. Panic-firewalled.
    pub fn block_ip(&self, uid: u32, cidr: String) -> bool {
        catch_unwind(AssertUnwindSafe(|| {
            let m = match CidrMatch::parse(&cidr) {
                Some(m) => m,
                None => return false,
            };
            let rule = IpRule {
                uid,
                cidr: m,
                port: PortSpec::Any,
                proto: ProtoSpec::Any,
                status: IpStatus::Block,
            };
            match self.engine.lock() {
                Ok(mut engine) => {
                    engine.add_cidr_rule(rule);
                    true
                }
                Err(_) => false,
            }
        }))
        .unwrap_or(false)
    }

    /// Install (REPLACE) a per-app matrix row (TIER 3). Overwrites any prior row for the UID. The cascade
    /// consults it on the app's next connection. Panic-firewalled to a no-op.
    pub fn set_app_row(&self, row: WardenAppRow) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut engine) = self.engine.lock() {
                engine.set_app_row(row.to_internal());
            }
        }));
    }

    /// Remove the per-app matrix row for `uid` (e.g. on app uninstall). The app reverts to the untracked /
    /// default-allow path. Panic-firewalled to a no-op.
    pub fn remove_app_row(&self, uid: u32) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut engine) = self.engine.lock() {
                engine.remove_app_row(uid);
            }
        }));
    }

    /// Read the held per-app matrix rows (TIER 3) — the control-plane READ the per-app firewall UI
    /// lists (each row = the durable user intent for one UID: mode, meteredness, temp-allow). The
    /// read direction [`set_app_row`](Self::set_app_row) never had: without it a UI could WRITE
    /// rows but never render the current posture (F1, e-fix round 2). Sorted by UID for a stable
    /// list order. Pure read; panic-firewalled / poisoned-lock → an empty list.
    pub fn app_rows(&self) -> Vec<WardenAppRow> {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => {
                let mut rows: Vec<WardenAppRow> = engine
                    .matrix
                    .rows()
                    .map(WardenAppRow::from_internal)
                    .collect();
                rows.sort_by_key(|r| r.uid);
                rows
            }
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// Enumerate the armed BLOCK domain rules (M2 — the settings-pane rule LIST + per-index REMOVE
    /// reader; the read direction [`install_domain_rules`](Self::install_domain_rules) never had). The
    /// reversed-label trie terminals (every one reports `wildcard = true` — the trie stores
    /// wildcard-at-apex, an exact rule subsumed by its apex terminal) PLUS the validated glob patterns
    /// (slice 3, the `*.example.com` form), so the enumerated count matches the snapshot's `domain_rules`
    /// tally (trie + globs — otherwise a glob rule would count in the header yet be invisible + un-removable
    /// in the list). The globs carry no per-uid tag in the live set, so they enumerate as universal
    /// (`uid = 0`). Pure read; panic-firewalled / poisoned lock → an empty list.
    pub fn domain_rules(&self) -> Vec<WardenDomainRule> {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => {
                let mut out: Vec<WardenDomainRule> = engine
                    .rule_sets
                    .domain
                    .rules()
                    .into_iter()
                    .map(|r| WardenDomainRule {
                        domain: r.domain.to_string(),
                        uid: r.uid,
                        wildcard: r.wildcard,
                    })
                    .collect();
                for p in &engine.rule_sets.glob_domains {
                    out.push(WardenDomainRule {
                        domain: p.source(),
                        uid: UID_UNIVERSAL,
                        wildcard: true,
                    });
                }
                out
            }
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// Enumerate the armed BLOCK/BYPASS CIDR rules (M2 — the settings-pane rule LIST + per-index REMOVE
    /// reader). Each live [`IpRule`] mapped back to its [`WardenCidrRule`] twin (v4 rules only — the wire
    /// net is a host-order `u32`; a v6 rule cannot round-trip the v4 wire and is skipped, never silently
    /// truncated to a wrong v4 net). Order is the finalized most-specific-first bucket order (uids ASC).
    /// Pure read; panic-firewalled / poisoned lock → an empty list.
    pub fn cidr_rules(&self) -> Vec<WardenCidrRule> {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => engine
                .rule_sets
                .cidr
                .rules()
                .into_iter()
                .filter_map(WardenCidrRule::from_internal)
                .collect(),
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// W-C (#86) — the v6-CAPABLE settings rule-list enumerator. Where [`cidr_rules`](Self::cidr_rules)
    /// DROPS every v6 rule (its `WardenCidrRule` wire net is a v4-only `u32`, so `from_internal` returns
    /// `None`), this emits EVERY armed CIDR rule — v4 AND v6 — as a tab wire row `"<uid>\t<text>\t<status>"`,
    /// so a v6 host block armed via [`block_ip`](Self::block_ip) is finally visible in the pane. `text` is
    /// the canonical CIDR string ([`format_cidr_rule`], `Ipv4Addr`/`Ipv6Addr` + `/prefix` + proto/port);
    /// `status` is `BLOCK`/`BYPASS`/`NONE`. Order is the finalized most-specific-first bucket order (uids
    /// ASC) — the SAME order [`remove_cidr_rule_at`](Self::remove_cidr_rule_at) indexes, so the rendered
    /// list and the per-index remove stay in lockstep (NO v6 index hazard). The `text` never holds a tab,
    /// so the Kotlin split is unambiguous. Pure read; panic-firewalled / poisoned lock -> an empty list.
    pub fn cidr_rules_wire(&self) -> Vec<String> {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => engine
                .rule_sets
                .cidr
                .rules()
                .into_iter()
                .map(|r| {
                    let status = match r.status {
                        IpStatus::Block => "BLOCK",
                        IpStatus::Bypass => "BYPASS",
                        IpStatus::None => "NONE",
                    };
                    format!("{}\t{}\t{}", r.uid, format_cidr_rule(&r), status)
                })
                .collect(),
            Err(_) => Vec::new(),
        }))
        .unwrap_or_default()
    }

    /// W-C (#86) — REMOVE the armed CIDR rule at flat index `index` in the [`cidr_rules_wire`] enumeration
    /// order (uids ASC, then finalized in-bucket). The v6-capable settings REMOVE: an index-remove needs NO
    /// reinstall, so a v6 rule (which the v4-only [`install_cidr_rules`](Self::install_cidr_rules) wire
    /// could not re-carry) is still removable — closing the other half of the v6 gap. Re-finalizes +
    /// flushes the decision cache via the engine. Returns `true` iff a rule was dropped. Panic-firewalled /
    /// poisoned lock / out-of-range index -> `false`.
    pub fn remove_cidr_rule_at(&self, index: u32) -> bool {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(mut engine) => engine.remove_cidr_rule_at(index as usize),
            Err(_) => false,
        }))
        .unwrap_or(false)
    }

    /// Install (REPLACE) the 9 universal DENY toggles (TIER 2, the `|||` settings section). A toggle fires
    /// only when BOTH its bit is set AND its matching universal rule is armed (defense-in-depth).
    /// Panic-firewalled to a no-op.
    pub fn set_universal_toggles(&self, toggles: WardenUniversalToggles) {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut engine) = self.engine.lock() {
                engine.set_universal_toggles(toggles.to_internal());
            }
        }));
    }

    /// Read back the 9 universal DENY toggles exactly as armed in the live engine (TIER 2) — the A6
    /// dashboard's chip state. The inverse of [`set_universal_toggles`](WardenObject::set_universal_toggles):
    /// a LIVE read of the engine's own bits, so the UI renders what the cascade actually consults (a
    /// Kotlin-side shadow could silently drift from a durable rehydrate). Pure read; panic-firewalled →
    /// all-`false` (the inert baseline).
    pub fn universal_toggles(&self) -> WardenUniversalToggles {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => WardenUniversalToggles::from_internal(engine.toggles),
            Err(_) => WardenUniversalToggles::default(),
        }))
        .unwrap_or_default()
    }

    /// Wire the per-app matrix + universal toggles to a DURABLE backing dir (RAM⊗NAND, slice 2) AND
    /// rehydrate the persisted posture from it. Call ONCE at boot, BEFORE any matrix/toggle mutation —
    /// the rehydrate REPLACES the in-memory toggles + REPOPULATES the matrix from the persisted blob, so a
    /// mutation issued before binding would be clobbered. `dir` is the app-private `filesDir` (the
    /// no-permission NAND tier, `allowBackup=false`); `now_ms` is the wall clock (`System.currentTimeMillis`)
    /// for the [RULE19] TempAllow TTL drop (a pause that lapsed while the device was OFF is restored
    /// expired). After binding, every control-plane matrix/toggle mutation auto-write-throughs (gentle,
    /// best-effort, NEVER on the verdict hot path). Returns the count of rows rehydrated (`0` = cold start /
    /// absent / corrupt — fail-safe). Panic-firewalled → `0`.
    pub fn bind_durable(&self, dir: String, now_ms: u64) -> u32 {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(mut engine) => engine.bind_durable(std::path::PathBuf::from(dir), now_ms) as u32,
            Err(_) => 0,
        }))
        .unwrap_or(0)
    }

    /// TempAllow TTL sweep (RULE19) — expire every per-app temp-allow whose wall-clock expiry passed
    /// `now_ms`, so an expired pause stops letting that app through (its per-app denies resume). The
    /// datapath drives this on its control plane (the verdict hot path holds no clock). If a durable dir
    /// is bound, an expiry gently write-throughs the new state. Returns the count expired. Panic-firewalled
    /// → `0`.
    ///
    /// NOTE: this explicit control-plane sweep (the Kotlin boot edge) is now COMPLEMENTED by the Object's
    /// OWN rate-limited verdict-edge sweep ([`Self::verdict`] / `verdict_internal` — at most once per
    /// [`TEMP_ALLOW_SWEEP_INTERVAL_MS`]), which covers the pauses granted MID-session on BOTH datapaths
    /// (Java gate + Rust tunnel). This method stays as the reboot-edge + manual sweep.
    pub fn expire_temp_allows(&self, now_ms: u64) -> u32 {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(mut engine) => engine.expire_temp_allows(now_ms) as u32,
            Err(_) => 0,
        }))
        .unwrap_or(0)
    }

    /// The dashboard's one-glance Warden status (the Object twin of the flat [`crate::warden_stats`] —
    /// richer, but the tallies are the SAME REAL [`Warden::stats`] the flat fn reads, never faked).
    /// Pure read; panic-firewalled → an all-zero snapshot.
    pub fn stats(&self) -> WardenSnapshot {
        self.snapshot()
    }

    /// Pull a [`WardenSnapshot`] of the live verdict tallies (per-tier deny attribution) + policy state +
    /// armed rule-set / matrix counts. Every number is a REAL read of the live engine (the object module
    /// is a DESCENDANT of `warden`, so it reads the engine's private fields directly — a LIVE read, no
    /// faked number). Pure read; panic-firewalled → an all-zero snapshot.
    pub fn snapshot(&self) -> WardenSnapshot {
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(engine) => {
                let s = engine.stats();
                WardenSnapshot {
                    allow: s.allow as i64,
                    deny: s.deny as i64,
                    deny_by_universal_toggle: s.deny_by_universal_toggle as i64,
                    deny_by_app: s.deny_by_app as i64,
                    deny_by_universal_rule: s.deny_by_universal_rule as i64,
                    deny_by_blocklist: s.deny_by_blocklist as i64,
                    // The engine is always armed once constructed (allow-by-default; the legacy
                    // WardenPolicy was removed) — a constant `true` preserves the snapshot surface.
                    policy_loaded: true,
                    fail_closed: engine.fail_closed,
                    cache_entries: engine.cache.len() as i64,
                    // Armed domain rules = the reversed-label trie terminals + the validated glob patterns
                    // (slice 3) — both are consulted deny rules, so both count honestly.
                    domain_rules: (engine.rule_sets.domain.len()
                        + engine.rule_sets.glob_domains.len())
                        as i64,
                    cidr_rules: engine.rule_sets.cidr.len() as i64,
                    universal_rules: engine.universal_rules.len() as i64,
                    app_rows: engine.matrix.len() as i64,
                }
            }
            Err(_) => zero_snapshot(),
        }))
        .unwrap_or_else(|_| zero_snapshot())
    }

    /// THE DNS-ANSWER VERDICT (slice 3) — judge a RESOLVED DNS answer (`name` + its resolved `addrs`, as
    /// strings) against the armed UNIVERSAL block rules: the plain-domain trie, the validated glob
    /// patterns (the dnsmasq per-label glob), and the family-aware CIDR blocks (v4 + v6). Returns
    /// [`WardenVerdict::DenyByFirewall`] when the name or ANY resolved address matches — the DNS resolver
    /// maps that to the TIER-5 `dns_blocked` flag the per-connection [`verdict`](WardenObject::verdict)
    /// then consumes (the single narrow seam). Unparseable addresses are skipped (a bad addr cannot match
    /// a CIDR — it abstains, never fabricates a deny).
    ///
    /// FAIL-SAFE = ABSTAIN (returns [`WardenVerdict::Allow`] on a poisoned lock / panic). This is an
    /// ADVISORY producer feeding the real per-connection gate; a fault here must NOT brick a name (the
    /// per-conn firewall remains the authority and still fails CLOSED on its own faults). DISTINCT from
    /// the per-conn verdict's fail-CLOSED — a producer that fabricated a block on a bug would NXDOMAIN a
    /// legitimate name, the connectivity-breaking hole the fail-safe law forbids.
    pub fn dns_verdict(&self, name: String, addrs: Vec<String>) -> WardenVerdict {
        let v = catch_unwind(AssertUnwindSafe(|| {
            let parsed: Vec<IpAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
            match self.engine.lock() {
                Ok(engine) => engine.dns_verdict(&name, &parsed),
                // A poisoned lock ⇒ ABSTAIN (advisory producer; the per-conn gate is the authority).
                Err(_) => Verdict::Allow,
            }
        }))
        .unwrap_or(Verdict::Allow);
        WardenVerdict::from_internal(v)
    }

    /// THE LOGGED DNS-ANSWER VERDICT (slice 6) — the Socio's review-channel seam. IDENTICAL to
    /// [`dns_verdict`](WardenObject::dns_verdict) (the same pure producer over the armed universal rules),
    /// PLUS it appends ONE human-legible line to the Warden's per-pillar `query-warden.log` (the #133
    /// [`crate::log_tier`] RAM⊗NAND substrate — the `query.log` precedent). The
    /// verdict computation stays pure; the log write is FAIL-OPEN and OFF the per-connection hot path — call
    /// THIS for the verdict feed, the plain [`dns_verdict`] for the hot resolver path. The line lands beside
    /// the matrix-state blob in the Warden's bound durable dir ([`bind_durable`](WardenObject::bind_durable));
    /// an UNBOUND Warden is a silent no-op (no dir → no log, never an error). `now_ms` is the injected wall
    /// clock (the warden clock-injection invariant); a no-op or failed log NEVER changes the returned verdict.
    ///
    /// FAIL-SAFE = ABSTAIN (returns [`WardenVerdict::Allow`] on a poisoned lock / panic), exactly as
    /// [`dns_verdict`] — an advisory producer must not brick a name on a fault.
    pub fn log_dns_verdict(&self, name: String, addrs: Vec<String>, now_ms: u64) -> WardenVerdict {
        let v = catch_unwind(AssertUnwindSafe(|| {
            let parsed: Vec<IpAddr> = addrs.iter().filter_map(|a| a.parse().ok()).collect();
            match self.engine.lock() {
                Ok(engine) => engine.dns_verdict_logged(&name, &parsed, now_ms),
                // A poisoned lock ⇒ ABSTAIN (advisory producer; the per-conn gate is the authority).
                Err(_) => Verdict::Allow,
            }
        }))
        .unwrap_or(Verdict::Allow);
        WardenVerdict::from_internal(v)
    }
}

/// UI PRE-FLIGHT (D27) — validate ONE domain rule against the RFC-1123 integrity gate WITHOUT arming
/// anything. Returns `Ok(())` when the rule would arm, or the typed [`WardenError`] naming exactly why it
/// would be rejected (over-broad `*.com`, bare TLD, illegal char, …). The add-rule screen calls this as a
/// user types so a bad rule is caught + explained BEFORE the install, instead of vanishing from the count.
/// Pure (no engine, no state, no IO); panic-firewalled to a typed [`WardenError::Panic`] — never an abort
/// across the FFI. (A flat free export, like `warden_stats` — no Object instance needed for a stateless
/// check; the same gate [`WardenObject::install_domain_rules`] runs at arm time.)
#[uniffi::export]
pub fn warden_validate_pattern(rule: String) -> Result<(), WardenError> {
    catch_unwind(AssertUnwindSafe(
        || match super::pattern::validate_pattern(&rule) {
            Ok(_) => Ok(()),
            Err(m) => Err(WardenError::from(m)),
        },
    ))
    .unwrap_or_else(|_| {
        Err(WardenError::Panic {
            reason: "panic in warden_validate_pattern".to_string(),
        })
    })
}

// ===========================================================================================
// THE CANONICAL DATAPATH INSTANCE (A6 — the one-engine convergence)
// ===========================================================================================
//
// Before A6 the app held THREE Warden engines that never met: the flat `lib.rs` global the Rust
// tunnel datapath consults via `torta_firewall_verdict` (never armed in production), the
// `WardenObject` the Kotlin `WardenDatapathGate` holds (the Java VPN datapath + the boot
// rehydrate + the classic control-plane land THERE), and libtorta_ui.so's cold rlib copy (the
// two-.so law — honest zeros). Rules armed on the gate's object were INVISIBLE to the Rust
// datapath; verdict tallies split across engines; the dashboard read the one engine nobody arms.
//
// A6 fix: ONE canonical process-global `Arc<WardenObject>`, minted here. Kotlin's gate `hold()`s
// THIS instance (via [`warden_datapath_instance`]) instead of constructing its own, so the boot
// rehydrate ([`WardenObject::bind_durable`]), the control-plane (rules / matrix / toggles), and
// the Java datapath verdicts all land on it — and the Rust tunnel gate (`tunnel/warden.rs`)
// consults the SAME engine via [`datapath_verdict`]. One engine, every surface: the Slint
// dashboard's counts, the LIVE FLOWS verdicts, and both datapaths finally agree.
//
// THE ENFORCE BIT: the user's firewall ARM switch. The Java datapath is already gated by
// `vpnPreferences.getFirewallEnabled()` on the Kotlin side; the Rust tunnel has no view of that
// pref, so Kotlin mirrors it here ([`warden_set_datapath_enforced`]). Default FALSE — the tunnel
// falls through to its legacy flat-global ask (which abstains unarmed): DISARMED SHIPS
// BYTE-IDENTICAL to the pre-A6 datapath. Construction alone never enforces: the boot rehydrate
// may populate the matrix while the user's switch stays off, and rows held by an UNENFORCED
// engine must not deny.

/// The one process-global Warden every surface converges on. `OnceLock` — minted on the first
/// [`warden_datapath_instance`] call (the Kotlin gate's `hold()`), never replaced. Instance-
/// isolated `WardenObject::new()` constructions (tests, previews) are unaffected: only THIS slot
/// is datapath-visible.
static DATAPATH: OnceLock<Arc<WardenObject>> = OnceLock::new();

/// The user's ARM switch, mirrored from Kotlin (`getFirewallEnabled()`-equivalent). `false` ⇒
/// [`datapath_verdict`] abstains (`None`) and the tunnel keeps its legacy path.
static DATAPATH_ENFORCED: AtomicBool = AtomicBool::new(false);

/// Get-or-mint THE canonical datapath Warden. Kotlin's `WardenDatapathGate.hold()` calls this
/// instead of `WardenObject()` so every control-plane write (rules / matrix / toggles / durable
/// rehydrate) arms the engine BOTH datapaths query. Idempotent; the same `Arc` every call.
#[uniffi::export]
pub fn warden_datapath_instance() -> Arc<WardenObject> {
    DATAPATH.get_or_init(WardenObject::new).clone()
}

/// Mirror the user's firewall ARM switch into the Rust datapath. Kotlin calls this from the A6
/// Slint ARM control (and re-asserts it at boot from the persisted pref). `false` (the default)
/// ⇒ the tunnel gate ignores the canonical engine entirely.
#[uniffi::export]
pub fn warden_set_datapath_enforced(on: bool) {
    DATAPATH_ENFORCED.store(on, Ordering::Release);
}

/// Read the ARM bit back (the UI's posture read — never a guess from construction state).
#[uniffi::export]
pub fn warden_datapath_enforced() -> bool {
    DATAPATH_ENFORCED.load(Ordering::Acquire)
}

/// THE TUNNEL'S CONSULT (crate-internal, the hot path). `None` unless the user ARMED the firewall
/// AND the canonical instance exists — the caller (`tunnel/warden.rs`) then falls through to its
/// legacy flat-global ask, byte-identical to pre-A6. `Some` carries the canonical engine's ruling
/// under the OBJECT's fault posture (fail-CLOSED on panic / poisoned lock — the same posture the
/// Java datapath gets from [`WardenObject::verdict`], so the two datapaths can never disagree on
/// a fault). Never constructs: minting is control-plane work, not verdict work.
pub(crate) fn datapath_verdict(conn: &ConnFacts) -> Option<Verdict> {
    if !DATAPATH_ENFORCED.load(Ordering::Acquire) {
        return None;
    }
    let obj = DATAPATH.get()?;
    Some(obj.verdict_internal(conn))
}

impl WardenObject {
    /// The internal-facts verdict — the tunnel hot path enters here, skipping the FFI-twin
    /// conversion ([`WardenConnFacts::to_internal`]) its caller never needed. Same lock, same
    /// engine cascade, same fail-CLOSED fault posture as [`WardenObject::verdict`] — and the same
    /// RULE19 verdict-edge sweep, so the Rust tunnel datapath honors a lapsed tap-pause exactly
    /// like the Java datapath does.
    pub(crate) fn verdict_internal(&self, conn: &ConnFacts) -> Verdict {
        let sweep_now = self.temp_allow_sweep_due();
        catch_unwind(AssertUnwindSafe(|| match self.engine.lock() {
            Ok(mut engine) => {
                if let Some(now_ms) = sweep_now {
                    let _ = engine.expire_temp_allows(now_ms);
                }
                engine.verdict(conn)
            }
            // A poisoned lock (impossible — verdict is panic-free arithmetic) ⇒ fail CLOSED.
            Err(_) => Verdict::Deny,
        }))
        // A panic in the gate ⇒ fail CLOSED (a bug must not leak).
        .unwrap_or(Verdict::Deny)
    }

    /// RULE19 — is the verdict-edge TempAllow sweep DUE? `Some(now_ms)` at most once per
    /// [`TEMP_ALLOW_SWEEP_INTERVAL_MS`] (a CAS decides the winner under concurrent verdicts);
    /// `None` otherwise. This closes the lapse the boot-edge-only sweep left open: a tap-pause
    /// GRANTED mid-session (the Kotlin granter's 1 h TTL) must expire mid-session too — before
    /// this, `expire_temp_allows` ran once per process (`RuntimeTierManager` pillar 2), so a
    /// runtime pause silently shielded that app's per-app denies until the next reboot.
    ///
    /// The engine's clock-injection law holds: the PURE cascade still takes no clock — the epoch
    /// read lives HERE, at the Object's impure boundary (the `mirror::object` SystemTime
    /// precedent), because the Rust tunnel datapath has no Kotlin caller to inject `now_ms`.
    /// A pre-epoch clock skips the sweep (best-effort — the boot-edge sweep still covers reboots).
    fn temp_allow_sweep_due(&self) -> Option<u64> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as u64;
        let last = self.last_temp_sweep_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < TEMP_ALLOW_SWEEP_INTERVAL_MS {
            return None;
        }
        // One winner per window: a lost CAS means a concurrent verdict owns this sweep.
        self.last_temp_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .ok()
            .map(|_| now_ms)
    }
}

/// The all-zero snapshot — the honest "off" a poisoned lock / panic falls to.
fn zero_snapshot() -> WardenSnapshot {
    WardenSnapshot {
        allow: 0,
        deny: 0,
        deny_by_universal_toggle: 0,
        deny_by_app: 0,
        deny_by_universal_rule: 0,
        deny_by_blocklist: 0,
        policy_loaded: false,
        fail_closed: false,
        cache_entries: 0,
        domain_rules: 0,
        cidr_rules: 0,
        universal_rules: 0,
        app_rows: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS-bearing Wi-Fi connection for `uid` querying `qname` (dns_blocked = false).
    fn conn(uid: u32, qname: Option<&str>) -> WardenConnFacts {
        WardenConnFacts {
            uid,
            daddr: "93.184.216.34".to_string(),
            dport: 443,
            proto: 6,
            qname: qname.map(|q| q.to_string()),
            net: WardenNetworkType::Wifi,
            dns_blocked: false,
        }
    }

    #[test]
    fn constructor_builds_allow_all_fail_safe_baseline() {
        let w = WardenObject::new();
        let snap = w.snapshot();
        assert_eq!(snap.allow, 0, "fresh ⇒ no verdicts yet");
        assert_eq!(snap.deny, 0);
        // A constructed allow-by-default engine is armed ⇒ policy_loaded is the constant `true`.
        assert!(
            snap.policy_loaded,
            "a constructed (allow-by-default) Warden reports armed"
        );
        assert!(!snap.fail_closed, "default posture is fail_closed = false");
        assert_eq!(snap.cache_entries, 0);
        assert_eq!(snap.domain_rules, 0);
        assert_eq!(snap.cidr_rules, 0);
        assert_eq!(snap.universal_rules, 0);
        assert_eq!(snap.app_rows, 0);
    }

    #[test]
    fn verdict_on_disabled_baseline_is_allow() {
        // firewall OFF (disabled baseline) + no rules/matrix/toggles ⇒ allow-all ⇒ Allow.
        let w = WardenObject::new();
        let v = w.verdict(conn(10_001, Some("example.com")));
        assert_eq!(v, WardenVerdict::Allow);
        let snap = w.snapshot();
        assert_eq!(snap.allow, 1);
        assert_eq!(snap.deny, 0);
        assert_eq!(snap.deny_by_blocklist, 0);
        assert_eq!(snap.cache_entries, 1);
    }

    #[test]
    fn verdict_with_malformed_daddr_fails_closed() {
        let w = WardenObject::new();
        let mut c = conn(10_001, None);
        c.daddr = "not-an-ip".to_string();
        // Unparseable daddr ⇒ fail CLOSED (DenyByFirewall), no panic.
        assert_eq!(w.verdict(c), WardenVerdict::DenyByFirewall);
    }

    #[test]
    fn dns_blocked_seam_denies_through_the_object() {
        // The TIER-5 dns_blocked seam — set by the resolver — denies through the Object's pure-firewall
        // verdict, and the snapshot attributes it to the blocklist seam.
        let w = WardenObject::new();
        let mut c = conn(10_001, Some("ads.example.com"));
        c.dns_blocked = true;
        assert_eq!(
            w.verdict(c),
            WardenVerdict::DenyByFirewall,
            "dns_blocked ⇒ a firewall deny"
        );
        let snap = w.snapshot();
        assert_eq!(snap.deny, 1);
        assert_eq!(
            snap.deny_by_blocklist, 1,
            "attributed to the TIER-5 seam in the snapshot"
        );
    }

    #[test]
    fn set_fail_closed_reflects_in_snapshot() {
        let w = WardenObject::new();
        w.set_fail_closed(true);
        assert!(w.snapshot().fail_closed, "fail-closed posture flipped");
        w.set_fail_closed(false);
        assert!(!w.snapshot().fail_closed);
    }

    #[test]
    fn install_domain_rules_arms_the_cascade_and_counts() {
        let w = WardenObject::new();
        let report = w.install_domain_rules(vec![
            WardenDomainRule {
                domain: "ads.example.com".to_string(),
                uid: 0, // universal
                wildcard: true,
            },
            WardenDomainRule {
                domain: "tracker.test".to_string(),
                uid: 10_001, // per-app
                wildcard: true,
            },
        ]);
        assert_eq!(report.accepted, 2, "two canonical domain rules installed");
        assert!(report.rejected.is_empty(), "no rejections for clean rules");
        assert_eq!(report.rejected_total, 0);
        assert_eq!(w.snapshot().domain_rules, 2);
        // WIRED: the universal rule now DENIES through the verdict (TIER 4).
        assert_eq!(
            w.verdict(conn(10_002, Some("ads.example.com"))),
            WardenVerdict::DenyByFirewall,
            "the armed universal domain rule denies through the pure-firewall verdict"
        );
        // A non-matching name passes.
        assert_eq!(
            w.verdict(conn(10_002, Some("good.example.com"))),
            WardenVerdict::Allow
        );
        // REPLACE semantics — a second install swaps the set.
        let report2 = w.install_domain_rules(vec![WardenDomainRule {
            domain: "solo.test".to_string(),
            uid: 0,
            wildcard: true,
        }]);
        assert_eq!(report2.accepted, 1);
        assert_eq!(w.snapshot().domain_rules, 1, "install REPLACES the set");
    }

    #[test]
    fn domain_rules_enumerates_trie_and_globs_round_trip() {
        // M2 — the LIST reader. A plain per-app rule + a plain universal rule land in the reversed-label
        // trie; a glob lands in the validated glob set. The enumerator UNIONs both, so the list length
        // matches the header count (a glob rule would otherwise count yet be invisible + un-removable).
        let w = WardenObject::new();
        let report = w.install_domain_rules(vec![
            WardenDomainRule {
                domain: "ads.example.com".to_string(),
                uid: 0,
                wildcard: true,
            },
            WardenDomainRule {
                domain: "tracker.test".to_string(),
                uid: 10_001,
                wildcard: true,
            },
            WardenDomainRule {
                domain: "*.metrics.net".to_string(),
                uid: 0,
                wildcard: true,
            },
        ]);
        assert_eq!(report.accepted, 3, "two trie rules + one glob armed");
        let rules = w.domain_rules();
        assert_eq!(
            rules.len(),
            3,
            "the enumerator returns every armed domain rule (trie + glob)"
        );
        assert_eq!(
            rules.len() as i64,
            w.snapshot().domain_rules,
            "list length matches the header tally"
        );
        assert!(
            rules.iter().all(|r| r.wildcard),
            "the trie stores every rule wildcard-at-apex"
        );
        assert!(rules
            .iter()
            .any(|r| r.domain == "ads.example.com" && r.uid == 0));
        assert!(rules
            .iter()
            .any(|r| r.domain == "tracker.test" && r.uid == 10_001));
        assert!(
            rules.iter().any(|r| r.domain == "*.metrics.net" && r.uid == 0),
            "the glob round-trips its source string"
        );
    }

    #[test]
    fn cidr_rules_enumerates_round_trip() {
        // M2 — the LIST reader for CIDR. A v4 BLOCK rule (203.0.113.0/24, any port/proto) + a v4 BYPASS
        // rule (10.0.0.1/32, tcp:443). Every field round-trips through the enumerator.
        let w = WardenObject::new();
        let n = w.install_cidr_rules(vec![
            WardenCidrRule {
                uid: 0,
                net: 0xCB00_7100, // 203.0.113.0
                prefix: 24,
                port: None,
                proto: None,
                status: WardenIpStatus::Block,
            },
            WardenCidrRule {
                uid: 10_005,
                net: 0x0A00_0001, // 10.0.0.1
                prefix: 32,
                port: Some(443),
                proto: Some(6),
                status: WardenIpStatus::Bypass,
            },
        ]);
        assert_eq!(n, 2, "two CIDR rules armed");
        let mut rules = w.cidr_rules();
        assert_eq!(rules.len(), 2, "the enumerator returns every armed CIDR rule");
        assert_eq!(
            rules.len() as i64,
            w.snapshot().cidr_rules,
            "list length matches the header tally"
        );
        rules.sort_by_key(|r| r.uid);
        let block = &rules[0];
        assert_eq!(block.uid, 0);
        assert_eq!(block.net, 0xCB00_7100);
        assert_eq!(block.prefix, 24);
        assert_eq!(block.port, None);
        assert_eq!(block.proto, None);
        assert_eq!(block.status, WardenIpStatus::Block);
        let bypass = &rules[1];
        assert_eq!(bypass.uid, 10_005);
        assert_eq!(bypass.net, 0x0A00_0001);
        assert_eq!(bypass.prefix, 32);
        assert_eq!(bypass.port, Some(443));
        assert_eq!(bypass.proto, Some(6));
        assert_eq!(bypass.status, WardenIpStatus::Bypass);
    }

    #[test]
    fn rule_remove_by_index_is_enumerate_drop_reinstall() {
        // M2 — the REMOVE contract. The Kotlin bridge removes rule i by re-installing the enumerated set
        // WITHOUT index i (install REPLACES the whole set). Prove that path in pure Rust.
        let w = WardenObject::new();
        w.install_domain_rules(vec![
            WardenDomainRule {
                domain: "a.example.com".to_string(),
                uid: 0,
                wildcard: true,
            },
            WardenDomainRule {
                domain: "b.example.com".to_string(),
                uid: 0,
                wildcard: true,
            },
            WardenDomainRule {
                domain: "c.example.com".to_string(),
                uid: 0,
                wildcard: true,
            },
        ]);
        let mut rules = w.domain_rules();
        assert_eq!(rules.len(), 3);
        // The enumerator sorts (uid ASC, domain ASC) ⇒ [a, b, c]; remove the middle one.
        assert_eq!(rules[1].domain, "b.example.com");
        rules.remove(1);
        let report = w.install_domain_rules(rules);
        assert_eq!(report.accepted, 2);
        let after = w.domain_rules();
        assert_eq!(after.len(), 2);
        assert!(
            after.iter().all(|r| r.domain != "b.example.com"),
            "the removed rule is gone"
        );
        assert!(after.iter().any(|r| r.domain == "a.example.com"));
        assert!(after.iter().any(|r| r.domain == "c.example.com"));
    }

    #[test]
    fn install_domain_rules_rejects_poisoned_overbroad_rules() {
        // SLICE 3 — the RFC-1123 integrity gate at the install boundary. A poisoned blocklist mixing an
        // over-broad `*.com` + a bare TLD `com` with two legit rules must arm ONLY the two legit ones.
        let w = WardenObject::new();
        let report = w.install_domain_rules(vec![
            WardenDomainRule {
                domain: "*.com".to_string(),
                uid: 0,
                wildcard: true,
            }, // REJECT (over-broad)
            WardenDomainRule {
                domain: "com".to_string(),
                uid: 0,
                wildcard: true,
            }, // REJECT (bare TLD)
            WardenDomainRule {
                domain: "ads.example.com".to_string(),
                uid: 0,
                wildcard: true,
            }, // keep
            WardenDomainRule {
                domain: "*.tracker.net".to_string(),
                uid: 0,
                wildcard: true,
            }, // keep (glob)
        ]);
        assert_eq!(
            report.accepted, 2,
            "only the two valid rules arm; the poison is rejected at the gate"
        );
        // D27: the two poison rules are REPORTED (not silently dropped), each with a typed reason.
        assert_eq!(report.rejected_total, 2, "both poison rules are reported");
        assert_eq!(report.rejected.len(), 2, "both fit under the report cap");
        assert!(
            report.rejected.iter().any(|r| r.rule == "*.com"),
            "the over-broad rule is named in the report"
        );
        assert!(
            report.rejected.iter().all(|r| !r.reason.is_empty()),
            "every rejection carries a human-legible reason"
        );
        assert_eq!(
            w.snapshot().domain_rules,
            2,
            "1 trie terminal + 1 validated glob"
        );
        // The over-broad `*.com` did NOT arm: a `.com` name the poison would have nuked is ALLOWED.
        assert_eq!(
            w.verdict(conn(10_001, Some("microsoft.com"))),
            WardenVerdict::Allow,
            "the rejected *.com must NOT block the internet"
        );
    }

    #[test]
    fn warden_validate_pattern_is_a_typed_preflight_d27() {
        // D27 — the UI add-rule pre-flight: a clean rule passes, the poison forms throw the typed reason.
        assert!(
            warden_validate_pattern("ads.example.com".to_string()).is_ok(),
            "a well-formed rule pre-flights OK"
        );
        assert!(
            warden_validate_pattern("*.tracker.net".to_string()).is_ok(),
            "a well-formed glob pre-flights OK"
        );
        assert_eq!(
            warden_validate_pattern("*.com".to_string()),
            Err(WardenError::OverBroad),
            "the over-broad `*.com` is rejected with the typed OverBroad reason"
        );
        assert_eq!(
            warden_validate_pattern("com".to_string()),
            Err(WardenError::TooFewLabels),
            "a bare TLD is rejected with TooFewLabels"
        );
        assert_eq!(
            warden_validate_pattern("   ".to_string()),
            Err(WardenError::Empty),
            "an empty rule is rejected with Empty"
        );
    }

    #[test]
    fn dns_verdict_denies_name_and_address_through_the_object() {
        // SLICE 3 — the DNS-answer verdict Object surface (the TIER-5 producer). Arm a universal domain
        // rule + a glob + a universal CIDR, then judge resolved answers.
        let w = WardenObject::new();
        w.install_domain_rules(vec![
            WardenDomainRule {
                domain: "ads.example.com".to_string(),
                uid: 0,
                wildcard: true,
            },
            WardenDomainRule {
                domain: "*.tracker.net".to_string(),
                uid: 0,
                wildcard: true,
            },
        ]);
        w.install_cidr_rules(vec![WardenCidrRule {
            uid: 0,
            net: u32::from("203.0.113.0".parse::<std::net::Ipv4Addr>().unwrap()),
            prefix: 24,
            port: None,
            proto: None,
            status: WardenIpStatus::Block,
        }]);

        // Name hit (plain trie).
        assert_eq!(
            w.dns_verdict("ads.example.com".to_string(), vec!["8.8.8.8".to_string()]),
            WardenVerdict::DenyByFirewall
        );
        // Name hit (glob).
        assert_eq!(
            w.dns_verdict("beacon.tracker.net".to_string(), vec![]),
            WardenVerdict::DenyByFirewall
        );
        // Address hit (clean name, a resolved addr in the blocked /24).
        assert_eq!(
            w.dns_verdict(
                "cdn.example.org".to_string(),
                vec!["203.0.113.50".to_string()]
            ),
            WardenVerdict::DenyByFirewall
        );
        // Clean name + clean addr ⇒ Allow (the producer abstains).
        assert_eq!(
            w.dns_verdict(
                "good.example.org".to_string(),
                vec!["93.184.216.34".to_string()]
            ),
            WardenVerdict::Allow
        );
        // An unparseable address is skipped (abstains, never a false deny).
        assert_eq!(
            w.dns_verdict(
                "good.example.org".to_string(),
                vec!["not-an-ip".to_string()]
            ),
            WardenVerdict::Allow
        );
    }

    #[test]
    fn cidr_wire_shows_v6_and_remove_at_drops_by_index() {
        // W-C (#86) — the v6 gap surfaced by D7: a v6 host block armed via block_ip must SHOW in the
        // v6-capable wire (where the v4-`u32` cidr_rules() DROPS it) and be REMOVABLE by its flat index
        // (where the v4-only install-REPLACE remove could not re-carry it). Arm a v4 /24 + a v6 /128,
        // both universal (uid 0). (ff02::16 = the IPv6 all-MLDv2-routers link-local group — a safe,
        // real v6 target; no resolver fixture.)
        let w = WardenObject::new();
        assert!(w.block_ip(0, "203.0.113.0/24".to_string()));
        assert!(w.block_ip(0, "ff02::16".to_string()));

        // The v4-only enumerator sees ONLY the v4 rule — the gap, reproduced.
        assert_eq!(
            w.cidr_rules().len(),
            1,
            "cidr_rules() (v4 u32 wire) drops the v6 rule"
        );
        // ...yet the held set (and the snapshot COUNT) holds BOTH — the count/list divergence.
        assert_eq!(
            w.snapshot().cidr_rules,
            2,
            "the engine holds both v4 + v6 (count saw what the list could not)"
        );

        // The v6-capable wire enumerates BOTH, v6 included, most-specific-first (v6 /128 spec 128 >
        // v4 /24 spec 96), tab-shaped "<uid>\t<text>\t<status>".
        let wire = w.cidr_rules_wire();
        assert_eq!(wire.len(), 2, "the wire enumerates v4 AND v6");
        assert_eq!(
            wire[0], "0\tff02::16/128\tBLOCK",
            "the v6 /128 host sorts most-specific-first, rendered compressed"
        );
        assert_eq!(wire[1], "0\t203.0.113.0/24\tBLOCK");

        // REMOVE the v6 rule by its flat index (0) — the half the v4 install wire could never do.
        assert!(
            w.remove_cidr_rule_at(0),
            "the v6 rule removes by its rendered index"
        );
        let after = w.cidr_rules_wire();
        assert_eq!(after.len(), 1, "only the v4 rule remains");
        assert_eq!(after[0], "0\t203.0.113.0/24\tBLOCK");
        assert_eq!(
            w.snapshot().cidr_rules,
            1,
            "the held count shrank in lockstep"
        );

        // An out-of-range index is a safe false — never a panic, never a wrong-rule drop.
        assert!(
            !w.remove_cidr_rule_at(9),
            "out-of-range index is a no-op false"
        );
    }

    #[test]
    fn install_cidr_rules_arms_the_cascade_and_counts() {
        let w = WardenObject::new();
        let n = w.install_cidr_rules(vec![
            WardenCidrRule {
                uid: 0,
                net: 0x5DB8_D800, // 93.184.216.0
                prefix: 24,
                port: None,
                proto: None,
                status: WardenIpStatus::Block,
            },
            WardenCidrRule {
                uid: 10_001,
                net: 0xC0A8_0000, // 192.168.0.0
                prefix: 16,
                port: Some(443),
                proto: Some(6),
                status: WardenIpStatus::Bypass,
            },
        ]);
        assert_eq!(n, 2);
        assert_eq!(w.snapshot().cidr_rules, 2);
        // WIRED: conn daddr 93.184.216.34 ∈ 93.184.216.0/24 (universal BLOCK) ⇒ deny.
        assert_eq!(
            w.verdict(conn(10_002, Some("x.example.com"))),
            WardenVerdict::DenyByFirewall,
            "the armed universal CIDR rule denies through the verdict"
        );
    }

    #[test]
    fn set_universal_rules_counts_in_snapshot() {
        let w = WardenObject::new();
        let n = w.set_universal_rules(vec![
            WardenUniversalRule::Lockdown,
            WardenUniversalRule::BlockMetered,
            WardenUniversalRule::BlockHttp,
        ]);
        assert_eq!(n, 3);
        assert_eq!(w.snapshot().universal_rules, 3);
    }

    #[test]
    fn universal_toggle_plus_rule_denies_through_the_object() {
        // A lockdown toggle is inert until the rule is armed (defense-in-depth); armed ⇒ TIER 2 deny.
        let w = WardenObject::new();
        w.set_universal_toggles(WardenUniversalToggles {
            lockdown: true,
            ..Default::default()
        });
        assert_eq!(
            w.verdict(conn(10_001, Some("x.example.com"))),
            WardenVerdict::Allow,
            "lockdown bit set but the rule UNARMED ⇒ inert"
        );
        w.set_universal_rules(vec![WardenUniversalRule::Lockdown]);
        assert_eq!(
            w.verdict(conn(10_001, Some("x.example.com"))),
            WardenVerdict::DenyByFirewall,
            "lockdown bit + rule armed ⇒ TIER 2 deny"
        );
        let snap = w.snapshot();
        assert_eq!(snap.deny_by_universal_toggle, 1, "attributed to TIER 2");
    }

    #[test]
    fn universal_toggles_read_back_round_trips_a6() {
        // A6: the dashboard chips render the ENGINE's bits — set through the export surface, read
        // back identical; a fresh object reads all-false (the inert baseline).
        let w = WardenObject::new();
        assert_eq!(
            w.universal_toggles(),
            WardenUniversalToggles::default(),
            "cold object ⇒ all-false"
        );
        let armed = WardenUniversalToggles {
            block_metered: true,
            device_lock: true,
            block_dns_bypass: true,
            ..Default::default()
        };
        w.set_universal_toggles(armed);
        let got = w.universal_toggles();
        assert!(
            got.block_metered && got.device_lock && got.block_dns_bypass,
            "the three armed bits read back set"
        );
        assert!(
            !got.block_new_apps
                && !got.block_unknown_conns
                && !got.lockdown
                && !got.block_background
                && !got.block_udp_ntp
                && !got.block_http,
            "the six unarmed bits read back clear"
        );
    }

    #[test]
    fn app_row_isolate_denies_and_counts() {
        let w = WardenObject::new();
        w.set_app_row(WardenAppRow {
            uid: 10_001,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 0,
        });
        assert_eq!(w.snapshot().app_rows, 1);
        // Isolate denies a non-LAN (Wifi) conn at TIER 3.
        assert_eq!(
            w.verdict(conn(10_001, Some("x.example.com"))),
            WardenVerdict::DenyByFirewall,
            "isolate denies a non-LAN conn"
        );
        assert_eq!(w.snapshot().deny_by_app, 1, "attributed to TIER 3");
        // remove_app_row reverts the app to default-allow.
        w.remove_app_row(10_001);
        assert_eq!(w.snapshot().app_rows, 0);
        assert_eq!(
            w.verdict(conn(10_001, Some("x.example.com"))),
            WardenVerdict::Allow,
            "after removing the row, the app reverts to allow-all"
        );
    }

    #[test]
    fn app_rows_reads_back_the_held_matrix_f1_efix2() {
        // F1 (e-fix round 2): the per-app firewall UI needs the READ direction — set two rows
        // through the export surface, read them back typed + UID-sorted, then remove one.
        let w = WardenObject::new();
        assert!(w.app_rows().is_empty(), "a fresh Warden holds no rows");
        w.set_app_row(WardenAppRow {
            uid: 10_002,
            mode: WardenAppMode::None,
            meteredness: WardenNetClass::Both,
            temp_allow_until: 0,
        });
        w.set_app_row(WardenAppRow {
            uid: 10_001,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 7_000,
        });
        let rows = w.app_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].uid, 10_001, "sorted by UID for a stable UI order");
        assert_eq!(rows[0].mode, WardenAppMode::Isolate);
        assert_eq!(rows[0].meteredness, WardenNetClass::Allow);
        assert_eq!(rows[0].temp_allow_until, 7_000, "round-trip is lossless");
        assert_eq!(rows[1].uid, 10_002);
        assert_eq!(rows[1].mode, WardenAppMode::None);
        assert_eq!(
            rows[1].meteredness,
            WardenNetClass::Both,
            "the block-all meteredness (the per-app internet-control block) survives the round-trip"
        );
        w.remove_app_row(10_002);
        let rows = w.app_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].uid, 10_001);
    }

    #[test]
    fn bypass_universal_skips_tier4_through_the_object() {
        // Arm a universal domain rule, then BypassUniversal must skip it (the scoped-matcher fix).
        let w = WardenObject::new();
        w.install_domain_rules(vec![WardenDomainRule {
            domain: "blocked.example.com".to_string(),
            uid: 0,
            wildcard: true,
        }]);
        assert_eq!(
            w.verdict(conn(10_001, Some("blocked.example.com"))),
            WardenVerdict::DenyByFirewall,
            "without bypass, the universal rule denies"
        );
        w.set_app_row(WardenAppRow {
            uid: 10_001,
            mode: WardenAppMode::BypassUniversal,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 0,
        });
        assert_eq!(
            w.verdict(conn(10_001, Some("blocked.example.com"))),
            WardenVerdict::Allow,
            "BypassUniversal skips the universal (TIER 4) rule"
        );
    }

    #[test]
    fn snapshot_is_consistent_across_reads() {
        let w = WardenObject::new();
        let _ = w.verdict(conn(10_001, Some("example.com")));
        let s1 = w.snapshot();
        let s2 = w.snapshot();
        assert_eq!(s1.allow, s2.allow);
        assert_eq!(s1.cache_entries, s2.cache_entries);
        assert_eq!(s1.policy_loaded, s2.policy_loaded);
    }

    #[test]
    fn enum_codes_match_the_stable_ordinal_contract() {
        assert_eq!(WardenVerdict::Allow.code(), 0);
        assert_eq!(WardenVerdict::DenyByFirewall.code(), 1);
        assert_eq!(WardenVerdict::DenyByBlocklist.code(), 2);
        assert_eq!(WardenNetworkType::Lan.code(), 0);
        assert_eq!(WardenNetworkType::Wifi.code(), 1);
        assert_eq!(WardenNetworkType::Gsm.code(), 2);
        assert_eq!(WardenNetworkType::Roaming.code(), 3);
        assert_eq!(WardenNetworkType::Vpn.code(), 4);
    }

    #[test]
    fn pure_firewall_never_attributes_a_blocklist_deny_without_the_seam() {
        // A qname that WOULD be on an external blocklist cannot produce a TIER-5 deny here unless the
        // resolver set dns_blocked — the Object does not re-query the blocklist (the seam is the only path).
        let w = WardenObject::new();
        let _ = w.verdict(conn(10_001, Some("known-ad-domain.example")));
        assert_eq!(
            w.snapshot().deny_by_blocklist,
            0,
            "no dns_blocked flag ⇒ no TIER-5 attribution"
        );
    }

    #[test]
    fn object_bind_durable_round_trips_and_expires_temp_allow() {
        // SLICE 2 through the UniFFI surface: bind_durable persists + rehydrates the matrix, and
        // expire_temp_allows honors the TempAllow TTL — both panic-firewalled, returning counts.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("torta-warden-obj-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_s = dir.to_string_lossy().into_owned();

        // Bind + arm an isolate row through the Object → auto-write-through.
        let w = WardenObject::new();
        assert_eq!(
            w.bind_durable(dir_s.clone(), 1_000),
            0,
            "cold start ⇒ 0 rows"
        );
        w.set_app_row(WardenAppRow {
            uid: 10_700,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 0,
        });

        // A fresh Object (the reboot) rehydrates the row from the same dir.
        let reborn = WardenObject::new();
        assert_eq!(
            reborn.bind_durable(dir_s.clone(), 1_000),
            1,
            "one row rehydrated through the Object"
        );
        assert_eq!(
            reborn.snapshot().app_rows,
            1,
            "the row survives the reboot through the Object surface"
        );
        assert_eq!(
            reborn.verdict(conn(10_700, Some("x.example.com"))),
            WardenVerdict::DenyByFirewall,
            "the rehydrated isolate row denies a non-LAN conn"
        );

        // expire_temp_allows through the Object: a paused row resumes its deny after the TTL lapses.
        // The pause is FAR-FUTURE (the RULE19 verdict-edge auto-sweep runs on a REAL wall clock now —
        // a tiny fake epoch would be honestly swept as lapsed before the first assert); the explicit
        // sweep then passes now_ms ≥ until to expire it.
        let w2 = WardenObject::new();
        w2.set_app_row(WardenAppRow {
            uid: 10_701,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: u64::MAX,
        });
        assert_eq!(
            w2.verdict(conn(10_701, Some("y.example.com"))),
            WardenVerdict::Allow,
            "an active (unlapsed) temp-allow pauses the isolate deny"
        );
        assert_eq!(
            w2.expire_temp_allows(u64::MAX),
            1,
            "the Object-level sweep expires the pause"
        );
        assert_eq!(
            w2.verdict(conn(10_701, Some("y.example.com"))),
            WardenVerdict::DenyByFirewall,
            "the isolate deny resumes after the Object-level TTL sweep"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule19_verdict_edge_sweep_clears_lapsed_pause_and_rate_limits() {
        // THE RUNTIME HALF of the TempAllow TTL (the confirmed half-complete): a pause GRANTED
        // mid-session must LAPSE mid-session. A lapsed pause (epoch-ms 1, decades past on the real
        // clock the edge sweep reads) is cleared by the FIRST verdict itself — the deny fires
        // immediately, no reboot needed.
        let w = WardenObject::new();
        w.set_app_row(WardenAppRow {
            uid: 10_800,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 1, // lapsed long ago vs the real wall clock
        });
        assert_eq!(
            w.verdict(conn(10_800, Some("a.example.com"))),
            WardenVerdict::DenyByFirewall,
            "the FIRST verdict sweeps the lapsed pause in the same lock hold — deny resumes NOW"
        );
        assert_eq!(
            w.app_rows()[0].temp_allow_until,
            0,
            "the lapsed pause was CLEARED to 0 (the contract: Object/datapath clears on expiry)"
        );

        // RATE LIMIT: the per-Object sweep just ran; a re-granted lapsed pause inside the same
        // 60 s window is NOT swept — the pause is honored until the next due window (≤60 s lag,
        // invisible against the 1 h TTL, and the hot path pays one atomic load + clock read).
        w.set_app_row(WardenAppRow {
            uid: 10_800,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 1,
        });
        assert_eq!(
            w.verdict(conn(10_800, Some("b.example.com"))),
            WardenVerdict::Allow,
            "inside the rate-limit window the sweep stays quiet — the pause row still shields"
        );
        assert_eq!(
            w.app_rows()[0].temp_allow_until,
            1,
            "unswept inside the window (the rate limiter is per-Object, deterministic in-test)"
        );

        // A FAR-FUTURE pause is never cleared by the sweep (only LAPSED pauses expire).
        let w2 = WardenObject::new();
        w2.set_app_row(WardenAppRow {
            uid: 10_801,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: u64::MAX,
        });
        assert_eq!(
            w2.verdict(conn(10_801, Some("c.example.com"))),
            WardenVerdict::Allow,
            "an unlapsed pause survives the edge sweep and still shields"
        );
        assert_eq!(w2.app_rows()[0].temp_allow_until, u64::MAX, "untouched");
    }

    #[test]
    fn rule19_edge_sweep_covers_the_tunnel_datapath_verdict_internal() {
        // The Rust tunnel datapath enters via `verdict_internal` (no Kotlin in the loop — no one can
        // inject now_ms). The SAME edge sweep must cover it: a lapsed pause clears on the first
        // internal verdict, so the tunnel honors RULE19 exactly like the Java datapath.
        let w = WardenObject::new();
        w.set_app_row(WardenAppRow {
            uid: 10_802,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 1, // lapsed long ago
        });
        let internal = conn(10_802, Some("d.example.com"))
            .to_internal()
            .expect("well-formed facts");
        assert_eq!(
            w.verdict_internal(&internal),
            Verdict::Deny,
            "the tunnel-path verdict sweeps the lapsed pause and denies"
        );
        assert_eq!(
            w.app_rows()[0].temp_allow_until,
            0,
            "cleared through the internal (tunnel) path too"
        );
    }

    #[test]
    fn log_dns_verdict_writes_through_the_ffi_surface() {
        // SLICE 6 through the UniFFI surface: bind a durable dir, arm a universal-domain block, and a
        // logged DNS-answer verdict appends to query-warden.log beside the matrix blob — the full FFI
        // write path. Unparseable addrs are skipped; the verdict is returned regardless of the log.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("torta-warden-objlog-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        let dir_s = dir.to_string_lossy().into_owned();

        let w = WardenObject::new();
        w.bind_durable(dir_s.clone(), 1_000);
        w.install_domain_rules(vec![WardenDomainRule {
            domain: "ads.evil.net".to_string(),
            uid: 0, // the universal tier
            wildcard: true,
        }]);

        assert_eq!(
            w.log_dns_verdict("ads.evil.net".to_string(), vec![], 1_751_300_000_000),
            WardenVerdict::DenyByFirewall,
            "a blocked answer denies through the logged FFI seam"
        );
        assert_eq!(
            w.log_dns_verdict(
                "ok.example.org".to_string(),
                vec!["93.184.216.34".to_string()],
                1_751_300_000_001
            ),
            WardenVerdict::Allow,
            "a clean answer allows through the logged FFI seam"
        );

        let body = std::fs::read_to_string(dir.join("query-warden.log"))
            .expect("query-warden.log was written through the FFI");
        assert!(
            body.contains("DENY ads.evil.net domain"),
            "the FFI-logged deny carries its reason: {body}"
        );
        assert!(
            body.contains("ALLOW ok.example.org - 93.184.216.34"),
            "the FFI-logged allow carries the resolved addr: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_dns_verdict_unbound_is_panic_safe_noop() {
        // An UNBOUND Object (no durable dir) — the logged verdict is a silent no-op for the log but still
        // returns the correct verdict; no panic crosses the FFI boundary.
        let w = WardenObject::new();
        w.install_domain_rules(vec![WardenDomainRule {
            domain: "ads.evil.net".to_string(),
            uid: 0,
            wildcard: true,
        }]);
        assert_eq!(
            w.log_dns_verdict("ads.evil.net".to_string(), vec![], 1_000),
            WardenVerdict::DenyByFirewall
        );
        assert_eq!(
            w.log_dns_verdict("ok.example.org".to_string(), vec![], 1_000),
            WardenVerdict::Allow
        );
    }

    // ---- THE CANONICAL DATAPATH INSTANCE (A6) --------------------------------------------------
    //
    // The canonical `DATAPATH` slot + `DATAPATH_ENFORCED` bit are PROCESS-GLOBAL and `OnceLock`
    // can never be cleared, so these tests (a) never assert absolute tallies on the canonical
    // instance, (b) use uids unique to this block (97_9xx), and (c) restore `enforced = false` +
    // remove their rows before returning (the single-thread test law makes that airtight).

    /// An internal-facts WAN connection (the tunnel hot-path shape — no FFI twin).
    fn dp_conn(uid: u32) -> ConnFacts {
        ConnFacts {
            uid,
            daddr: "93.184.216.34".parse().unwrap(),
            dport: 443,
            proto: 6,
            qname: None,
            net: NetworkType::Wifi,
            dns_blocked: false,
        }
    }

    #[test]
    fn datapath_disarmed_abstains_and_instance_is_canonical() {
        warden_set_datapath_enforced(false);
        assert!(!warden_datapath_enforced(), "the ARM bit reads back false");

        // Minting the instance does NOT arm the datapath — construction is control-plane work.
        let a = warden_datapath_instance();
        let b = warden_datapath_instance();
        assert!(Arc::ptr_eq(&a, &b), "one canonical Arc, every call");
        assert_eq!(
            datapath_verdict(&dp_conn(97_900)),
            None,
            "disarmed ⇒ the tunnel consult abstains even with the instance minted"
        );

        warden_set_datapath_enforced(true);
        assert!(warden_datapath_enforced(), "the ARM bit reads back true");
        warden_set_datapath_enforced(false);
    }

    #[test]
    fn datapath_enforced_rules_through_the_canonical_engine() {
        let w = warden_datapath_instance();
        // Arm an Isolate row (only DNS + LAN pass) for a uid unique to this test.
        w.set_app_row(WardenAppRow {
            uid: 97_901,
            mode: WardenAppMode::Isolate,
            meteredness: WardenNetClass::Allow,
            temp_allow_until: 0,
        });
        warden_set_datapath_enforced(true);

        assert_eq!(
            datapath_verdict(&dp_conn(97_901)),
            Some(Verdict::Deny),
            "an Isolate row armed on the CANONICAL engine denies its WAN conn via the tunnel consult"
        );
        assert_eq!(
            datapath_verdict(&dp_conn(97_902)),
            Some(Verdict::Allow),
            "an unruled uid still allows (allow-by-default cascade, ruled — not abstained)"
        );

        // Flip the ARM bit off — the SAME armed row goes silent (the switch, not the rules, gates).
        warden_set_datapath_enforced(false);
        assert_eq!(
            datapath_verdict(&dp_conn(97_901)),
            None,
            "disarming abstains instantly; armed rows on an unenforced engine never deny"
        );
        w.remove_app_row(97_901);
    }
}
