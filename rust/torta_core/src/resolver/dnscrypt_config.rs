/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! K5 — the **triple-duty** DNSCrypt configuration authority.
//!
//! [`DnscryptProxyConfig`] serves THREE roles from ONE struct (the de-InviZible Genesis: the config
//! became Rust-native, the TOML is now a *view*, never the authority):
//!
//! 1. **typed config authority** — the production source of truth the resolver is driven from;
//! 2. **serde TOML import/export model** — `toml::from_str` imports an existing `dnscrypt-proxy.toml`
//!    (the migration path) and `toml::to_string_pretty` exports one back (the Go-fallback +
//!    upstream-ecosystem COMPATIBILITY view). The TOML is NEVER the authority — it is a serialization
//!    of the Rust struct;
//! 3. **`uniffi::Record`** — surfaced to Kotlin as a typed data class (full-power UniFFI: every block is
//!    a typed nested Record, NEVER a flat string).
//!
//! It covers the FULL `example-dnscrypt-proxy.toml` field set — 60 top-level fields + 17 `[table]`
//! sub-Records (+ 6 helper Records). All DNSCrypt capabilities are represented typed and lossless:
//! relay routing (`anonymized_dns.routes`, the 0x81 multi-hop) · loopback listener (`local_doh`) ·
//! DNS64 (`dns64.prefix`/`resolver`) · server selection (`server_names`/`sources`/`lb_strategy`) ·
//! the requirements (`require_dnssec`/`require_nolog`/`require_nofilter`) · the version-sync source
//! refresh (`sources.*.refresh_delay`/`cache_ttl`).
//!
//! ## Build-breakers honoured (measured in the ground phase, NOT asserted)
//!
//! - **B2 — toml-rs needs all VALUES before all TABLES.** `toml::to_string*` errors *"values must be
//!   emitted before tables"* if any scalar/array is declared AFTER a sub-table. So all ~60 top-level
//!   scalar/array fields are declared FIRST, then all 17 sub-Record fields LAST. The same rule is
//!   honoured inside each sub-Record (scalars before any array-of-tables, e.g. [`AnonymizedDns`]).
//! - **B3 — partial-import must land on UPSTREAM defaults, not type-zeros.** A `#[derive(Default)]` (or
//!   a container-level `#[serde(default)]`) would zero each ★ active field (`cache=false`, `timeout=0`,
//!   `require_nolog=false`, `listen_addresses=[]`) — a security regression on a partial TOML. So EVERY
//!   active-default field carries its OWN `#[serde(default = "def_*")]` returning the upstream value, and
//!   [`DnscryptProxyConfig`] has a **hand-written** `impl Default` (NOT derived) that calls the SAME
//!   `def_*` helpers — one source of truth per default, so `import(..).unwrap_or_default()` is safe.
//! - **B5 — `netprobe_timeout` is signed `i32`** (`-1` = "wait as much as possible" is documented-valid).
//! - **B6 — `timeout_load_reduction` is the only float** (`f64`, range 0.0–1.0).
//! - **B7 — `blocked_query_response` defaults to `"hinfo"`** (REQUIRED for Android 8+, not the example's
//!   first-listed `"refused"`); Tortä is Android, so the default + export bake in `hinfo`.
//! - **B8 — open enum sets stay `String`.** `lb_strategy` (the `p<n>` form is open), `format`, and
//!   `ip_encryption.algorithm` are kept as `String` (conservative round-trip — survives upstream adding a
//!   variant) rather than `uniffi::Enum`.
//!
//! Int policy: `i32` uniformly (every value fits; avoids UniFFI→Kotlin `UInt` friction).
//!
//! Dead-code-until-wired: the lib.rs `#[uniffi::export]` front-door (`dnscrypt_config_from_toml` /
//! `_to_toml` / `_apply`) + the `configure_from` orchestrator land in a SUBSEQUENT slice; this module is
//! the typed surface they will drive (the `rotation`/`listener` `pub(crate)` precedent).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The full DNSCrypt-proxy configuration — the typed authority, the serde TOML model, and the
/// `uniffi::Record` Kotlin data class, in one struct (see the module docs for the triple-duty contract).
///
/// Field order is load-bearing (B2): all top-level scalar/array VALUES first, then all `[table]`
/// sub-Records last, so `toml::to_string_pretty` never hits "values must be emitted before tables".
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct DnscryptProxyConfig {
    // ===================================================================================================
    // Section A — top-level scalars + arrays (VALUES; declared BEFORE every table, B2)
    // ===================================================================================================
    /// Explicit server names to use; empty = pick from the loaded sources.
    #[serde(default)]
    pub server_names: Vec<String>,
    /// Local addresses the proxy listens on (the loopback listener view). Default `['127.0.0.1:53']`.
    #[serde(default = "def_listen")]
    pub listen_addresses: Vec<String>,
    /// Max simultaneous client connections.
    #[serde(default = "def_250")]
    pub max_clients: i32,
    /// Drop privileges to this user after binding (absent on Android).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// Use servers reachable over IPv4.
    #[serde(default = "def_true")]
    pub ipv4_servers: bool,
    /// Use servers reachable over IPv6.
    #[serde(default)]
    pub ipv6_servers: bool,
    /// Use DNSCrypt servers.
    #[serde(default = "def_true")]
    pub dnscrypt_servers: bool,
    /// Use DoH servers.
    #[serde(default = "def_true")]
    pub doh_servers: bool,
    /// Use Oblivious DoH servers.
    #[serde(default)]
    pub odoh_servers: bool,
    /// Only use servers implementing DNSSEC.
    #[serde(default)]
    pub require_dnssec: bool,
    /// Only use servers that don't log user queries.
    #[serde(default = "def_true")]
    pub require_nolog: bool,
    /// Only use servers that don't enforce their own blocklist.
    #[serde(default = "def_true")]
    pub require_nofilter: bool,
    /// Server names to avoid even if in a source.
    #[serde(default)]
    pub disabled_server_names: Vec<String>,
    /// Always use TCP to connect to upstreams.
    #[serde(default)]
    pub force_tcp: bool,
    /// Enable HTTP/3 (QUIC) for DoH.
    #[serde(default)]
    pub http3: bool,
    /// Probe HTTP/3 support in the background, switch when faster.
    #[serde(default)]
    pub http3_probe: bool,
    /// ★ PQDNSCrypt — negotiate X-Wing post-quantum certs (es-version 0x0003, "DNSCrypt 2026") when a
    /// resolver publishes one. Upstream v2.1.17's `pqdnscrypt` toggle, default ON (their default too):
    /// with a valid PQ cert on offer the es-major selection never downgrades to classic; `false` skips
    /// PQ certs entirely. Tortä divergence (documented at `pq_encrypted_exchange`): a FRESH X-Wing
    /// encapsulation every query, no resume tickets — per-query unlinkability over resume bandwidth.
    #[serde(default = "def_true")]
    pub pqdnscrypt: bool,
    /// SOCKS proxy for all connections (`socks5://…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// HTTP/HTTPS proxy for DoH only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_proxy: Option<String>,
    /// How long a DNS query waits for a response, in milliseconds.
    #[serde(default = "def_5000")]
    pub timeout: i32,
    /// Keepalive for HTTP (HTTPS, HTTP/2) connections, in seconds.
    #[serde(default = "def_30")]
    pub keepalive: i32,
    /// EDNS client-subnet values to send (privacy: usually empty).
    #[serde(default)]
    pub edns_client_subnet: Vec<String>,
    /// Response sent to blocked queries. Default `"hinfo"` (REQUIRED on Android 8+, B7).
    #[serde(default = "def_hinfo", skip_serializing_if = "Option::is_none")]
    pub blocked_query_response: Option<String>,
    /// Load-balancing strategy (`p2`/`ph`/`fastest`/`random`/`wp2`…); open set, kept `String` (B8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_strategy: Option<String>,
    /// Estimate effective latency to refine load balancing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lb_estimator: Option<bool>,
    /// Fraction of `timeout` used when the network is slow (0.0–1.0); the ONLY float (B6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_load_reduction: Option<f64>,
    /// Reload config/rules on change without a restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_hot_reload: Option<bool>,
    /// Verbosity 0 (debug) … 6 (critical).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<i32>,
    /// Log file path (instead of stderr).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Append `-latest` symlink to the most recent log file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file_latest: Option<bool>,
    /// Use the system logger (syslog on *nix, Event Log on Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_syslog: Option<bool>,
    /// Max log file size in MB before rotation.
    #[serde(default = "def_10")]
    pub log_files_max_size: i32,
    /// Max age in days for a rotated log file.
    #[serde(default = "def_7")]
    pub log_files_max_age: i32,
    /// Max number of rotated log backups to keep.
    #[serde(default = "def_1")]
    pub log_files_max_backups: i32,
    /// How many certificates to fetch concurrently on refresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_refresh_concurrency: Option<i32>,
    /// Certificate refresh cadence, in minutes.
    #[serde(default = "def_240")]
    pub cert_refresh_delay: i32,
    /// Accept certificates even when the local clock looks wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_ignore_timestamp: Option<bool>,
    /// Use ephemeral keys for DNSCrypt (anonymity vs reuse).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnscrypt_ephemeral_keys: Option<bool>,
    /// Disable TLS session tickets (DoH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_disable_session_tickets: Option<bool>,
    /// Prefer RSA over ECDSA in the TLS handshake (DoH).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_prefer_rsa: Option<bool>,
    /// File to dump TLS session keys to (debug only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_log_file: Option<String>,
    /// Bootstrap resolvers used to resolve server hostnames. Default `['9.9.9.11:53','8.8.8.8:53']`.
    #[serde(default = "def_bootstrap")]
    pub bootstrap_resolvers: Vec<String>,
    /// Never fall back to the system DNS, even before bootstrap completes.
    #[serde(default = "def_true")]
    pub ignore_system_dns: bool,
    /// Connectivity-check timeout in seconds (`-1` = wait as much as possible, `0` = no test; B5).
    #[serde(default = "def_60")]
    pub netprobe_timeout: i32,
    /// Address probed for initial connectivity (no traffic exchanged).
    #[serde(default = "def_netprobe")]
    pub netprobe_address: String,
    /// Enable offline mode (use only the local cache + cloaking/blocking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_mode: Option<bool>,
    /// Additional metadata to attach to outgoing queries.
    #[serde(default)]
    pub query_meta: Vec<String>,
    /// Immediately respond to IPv6 (AAAA) queries with an empty answer.
    #[serde(default)]
    pub block_ipv6: bool,
    /// Immediately respond to A/AAAA for names without a public suffix.
    #[serde(default = "def_true")]
    pub block_unqualified: bool,
    /// Immediately respond to queries for undelegated local zones.
    #[serde(default = "def_true")]
    pub block_undelegated: bool,
    /// TTL (seconds) of a synthesized rejection (blocked/cloaked).
    #[serde(default = "def_10")]
    pub reject_ttl: i32,
    /// Path to forwarding rules (`server=/domain/ip`); FILE pointer, not inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarding_rules: Option<String>,
    /// Path to cloaking rules (`name ip`); FILE pointer, not inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloaking_rules: Option<String>,
    /// TTL (seconds) for cloaked responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloak_ttl: Option<i32>,
    /// Also cloak the PTR (reverse) of cloaked IPs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloak_ptr: Option<bool>,
    /// Enable the in-memory DNS cache.
    #[serde(default = "def_true")]
    pub cache: bool,
    /// Cache capacity (entries).
    #[serde(default = "def_4096")]
    pub cache_size: i32,
    /// Minimum TTL (seconds) for a cached entry.
    #[serde(default = "def_2400")]
    pub cache_min_ttl: i32,
    /// Maximum TTL (seconds) for a cached entry.
    #[serde(default = "def_86400")]
    pub cache_max_ttl: i32,
    /// Serve-stale window (seconds): answer instantly from an EXPIRED entry while a fresh copy is
    /// fetched in the background (RFC 8767). 0 = disabled.
    ///
    /// ★ #92 — added because the MaskSolver serve-stale stepper had NO home in this authority: it
    /// could be neither seeded from the record nor persisted to it, so its value died with the
    /// process while its four siblings (cache_size, timeout, cache_min_ttl, cache_max_ttl) survived.
    /// Plain `#[serde(default)]` (0 for i32) rather than a `def_*` helper: absent-in-record and
    /// explicitly-off are the SAME state for this field, so they should decode identically — and an
    /// older record written before this field existed must rehydrate as "off", never as a surprise
    /// stale window the user never chose.
    #[serde(default)]
    pub serve_stale_secs: i32,
    /// Minimum TTL (seconds) for a cached negative (NXDOMAIN) entry.
    #[serde(default = "def_60")]
    pub cache_neg_min_ttl: i32,
    /// Maximum TTL (seconds) for a cached negative (NXDOMAIN) entry.
    #[serde(default = "def_600")]
    pub cache_neg_max_ttl: i32,

    // ===================================================================================================
    // Section B — the [table] sections (TABLES; declared LAST, B2). Each is its own nested uniffi::Record.
    // ===================================================================================================
    /// `[captive_portals]` — names answered locally to satisfy captive-portal probes.
    #[serde(default)]
    pub captive_portals: CaptivePortals,
    /// `[local_doh]` — a local DoH server endpoint (the loopback-listener view).
    #[serde(default)]
    pub local_doh: LocalDoh,
    /// `[query_log]` — the query log sink.
    #[serde(default)]
    pub query_log: QueryLog,
    /// `[nx_log]` — the NXDOMAIN/SERVFAIL log sink.
    #[serde(default)]
    pub nx_log: NxLog,
    /// `[blocked_names]` — name-pattern blocklist.
    #[serde(default)]
    pub blocked_names: BlockedNames,
    /// `[blocked_ips]` — answer-IP blocklist.
    #[serde(default)]
    pub blocked_ips: BlockedIps,
    /// `[allowed_names]` — name-pattern allowlist (overrides blocking).
    #[serde(default)]
    pub allowed_names: AllowedNames,
    /// `[allowed_ips]` — answer-IP allowlist.
    #[serde(default)]
    pub allowed_ips: AllowedIps,
    /// `[schedules.<name>]` — named weekly time-window schedules referenced by blocklists.
    #[serde(default)]
    pub schedules: HashMap<String, WeeklySchedule>,
    /// `[sources.<name>]` — the resolver/relay list sources (carries the 0x81 relays + version-sync).
    #[serde(default)]
    pub sources: HashMap<String, Source>,
    /// `[broken_implementations]` — servers whose oversized-response handling needs fragment blocking.
    #[serde(default)]
    pub broken_implementations: BrokenImplementations,
    /// `[doh_client_x509_auth]` — client-certificate credentials for mutual-TLS DoH.
    #[serde(default)]
    pub doh_client_x509_auth: DohClientX509Auth,
    /// `[anonymized_dns]` — Anonymized DNSCrypt relay routing (the 0x81 multi-hop the LAW keeps intact).
    #[serde(default)]
    pub anonymized_dns: AnonymizedDns,
    /// `[dns64]` — DNS64 NAT64 prefix synthesis.
    #[serde(default)]
    pub dns64: Dns64,
    /// `[ip_encryption]` — client-IP encryption for the query log.
    #[serde(default)]
    pub ip_encryption: IpEncryption,
    /// `[monitoring_ui]` — the optional embedded monitoring web UI.
    #[serde(default)]
    pub monitoring_ui: MonitoringUi,
    /// `[static.<name>]` — extra servers pinned by their `sdns://` stamp. Rust name avoids the keyword.
    #[serde(rename = "static", default)]
    pub static_servers: HashMap<String, StaticServer>,
}

impl Default for DnscryptProxyConfig {
    /// Hand-written (NOT derived) so a partial import lands on UPSTREAM defaults, never type-zeros (B3).
    /// Each active default calls the SAME `def_*` helper the serde attribute names — one source of truth.
    fn default() -> Self {
        Self {
            // Section A
            server_names: Vec::new(),
            listen_addresses: def_listen(),
            max_clients: def_250(),
            user_name: None,
            ipv4_servers: def_true(),
            ipv6_servers: false,
            dnscrypt_servers: def_true(),
            doh_servers: def_true(),
            odoh_servers: false,
            require_dnssec: false,
            require_nolog: def_true(),
            require_nofilter: def_true(),
            disabled_server_names: Vec::new(),
            force_tcp: false,
            http3: false,
            http3_probe: false,
            pqdnscrypt: def_true(),
            proxy: None,
            http_proxy: None,
            timeout: def_5000(),
            keepalive: def_30(),
            edns_client_subnet: Vec::new(),
            blocked_query_response: def_hinfo(),
            lb_strategy: None,
            lb_estimator: None,
            timeout_load_reduction: None,
            enable_hot_reload: None,
            log_level: None,
            log_file: None,
            log_file_latest: None,
            use_syslog: None,
            log_files_max_size: def_10(),
            log_files_max_age: def_7(),
            log_files_max_backups: def_1(),
            cert_refresh_concurrency: None,
            cert_refresh_delay: def_240(),
            cert_ignore_timestamp: None,
            dnscrypt_ephemeral_keys: None,
            tls_disable_session_tickets: None,
            tls_prefer_rsa: None,
            tls_key_log_file: None,
            bootstrap_resolvers: def_bootstrap(),
            ignore_system_dns: def_true(),
            netprobe_timeout: def_60(),
            netprobe_address: def_netprobe(),
            offline_mode: None,
            query_meta: Vec::new(),
            block_ipv6: false,
            block_unqualified: def_true(),
            block_undelegated: def_true(),
            reject_ttl: def_10(),
            forwarding_rules: None,
            cloaking_rules: None,
            cloak_ttl: None,
            cloak_ptr: None,
            cache: def_true(),
            cache_size: def_4096(),
            cache_min_ttl: def_2400(),
            // ★ #92 — serve-stale defaults OFF: answering from an expired entry is a resilience
            // trade the user opts into, never a default they inherit.
            serve_stale_secs: 0,
            cache_max_ttl: def_86400(),
            cache_neg_min_ttl: def_60(),
            cache_neg_max_ttl: def_600(),
            // Section B
            captive_portals: CaptivePortals::default(),
            local_doh: LocalDoh::default(),
            query_log: QueryLog::default(),
            nx_log: NxLog::default(),
            blocked_names: BlockedNames::default(),
            blocked_ips: BlockedIps::default(),
            allowed_names: AllowedNames::default(),
            allowed_ips: AllowedIps::default(),
            schedules: HashMap::new(),
            sources: HashMap::new(),
            broken_implementations: BrokenImplementations::default(),
            doh_client_x509_auth: DohClientX509Auth::default(),
            anonymized_dns: AnonymizedDns::default(),
            dns64: Dns64::default(),
            ip_encryption: IpEncryption::default(),
            monitoring_ui: MonitoringUi::default(),
            static_servers: HashMap::new(),
        }
    }
}

// =======================================================================================================
// Section B sub-Records — each a nested uniffi::Record. Within each, scalars/arrays precede any
// array-of-tables field (B2). All-zero defaults derive Default; active defaults hand-write it.
// =======================================================================================================

/// `[captive_portals]` — a file of names answered locally to satisfy captive-portal probes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct CaptivePortals {
    /// Path to the captive-portal map file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_file: Option<String>,
}

/// `[local_doh]` — a local DoH endpoint served by the proxy (the loopback-listener view).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct LocalDoh {
    /// Addresses the local DoH server listens on (distinct from the top-level `listen_addresses`).
    #[serde(default)]
    pub listen_addresses: Vec<String>,
    /// URL path of the DoH endpoint (e.g. `/dns-query`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// TLS certificate file for the local DoH server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_file: Option<String>,
    /// TLS private-key file for the local DoH server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_key_file: Option<String>,
}

/// `[query_log]` — where resolved queries are logged.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct QueryLog {
    /// Log file path; absent = no query log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Log format: `"tsv"` (default) or `"ltsv"`. Open-ish set kept `String` (B8).
    #[serde(default = "def_tsv")]
    pub format: String,
    /// Query types NOT logged (e.g. `["AAAA"]`).
    #[serde(default)]
    pub ignored_qtypes: Vec<String>,
}

impl Default for QueryLog {
    fn default() -> Self {
        Self {
            file: None,
            format: def_tsv(),
            ignored_qtypes: Vec::new(),
        }
    }
}

/// `[nx_log]` — where NXDOMAIN/SERVFAIL responses are logged.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct NxLog {
    /// Log file path; absent = no NX log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Log format: `"tsv"` (default) or `"ltsv"`.
    #[serde(default = "def_tsv")]
    pub format: String,
}

impl Default for NxLog {
    fn default() -> Self {
        Self {
            file: None,
            format: def_tsv(),
        }
    }
}

/// `[blocked_names]` — name-pattern blocklist.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BlockedNames {
    /// Path to the blocked-names rules file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_names_file: Option<String>,
    /// Path to log blocked-name hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Log format for blocked-name hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
}

/// `[blocked_ips]` — answer-IP blocklist.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BlockedIps {
    /// Path to the blocked-IPs rules file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_ips_file: Option<String>,
    /// Path to log blocked-IP hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Log format for blocked-IP hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
}

/// `[allowed_names]` — name-pattern allowlist (overrides blocking).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct AllowedNames {
    /// Path to the allowed-names rules file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_names_file: Option<String>,
    /// Path to log allowed-name hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Log format for allowed-name hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
}

/// `[allowed_ips]` — answer-IP allowlist.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct AllowedIps {
    /// Path to the allowed-IPs rules file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips_file: Option<String>,
    /// Path to log allowed-IP hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    /// Log format for allowed-IP hits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_format: Option<String>,
}

/// One inline `{ after = '..', before = '..' }` time window.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct TimeRange {
    /// Window start (e.g. `"09:00"`).
    pub after: String,
    /// Window end (e.g. `"18:00"`).
    pub before: String,
}

/// `[schedules.<name>]` — a weekly schedule, one array-of-time-ranges per day.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct WeeklySchedule {
    #[serde(default)]
    pub mon: Vec<TimeRange>,
    #[serde(default)]
    pub tue: Vec<TimeRange>,
    #[serde(default)]
    pub wed: Vec<TimeRange>,
    #[serde(default)]
    pub thu: Vec<TimeRange>,
    #[serde(default)]
    pub fri: Vec<TimeRange>,
    #[serde(default)]
    pub sat: Vec<TimeRange>,
    #[serde(default)]
    pub sun: Vec<TimeRange>,
}

/// `[sources.<name>]` — a resolver/relay list source (carries the relays.md the 0x81 routing draws from).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct Source {
    /// Mirror URLs for the list.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Local cache file for the fetched list.
    pub cache_file: String,
    /// Minisign public key that signs the list.
    pub minisign_key: String,
    /// Per-source refresh cadence in hours (distinct from the top-level `cert_refresh_delay`, B9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_delay: Option<i32>,
    /// Prefix applied to every server name from this source.
    #[serde(default)]
    pub prefix: String,
    /// Optional cache TTL override in hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl: Option<i32>,
}

/// `[broken_implementations]` — servers needing DNS-fragment blocking (oversized-response workaround).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct BrokenImplementations {
    /// Server names that cannot handle fragmented responses (active 11-entry default list).
    #[serde(default = "def_fragments")]
    pub fragments_blocked: Vec<String>,
}

impl Default for BrokenImplementations {
    fn default() -> Self {
        Self {
            fragments_blocked: def_fragments(),
        }
    }
}

/// One mutual-TLS client credential for `[doh_client_x509_auth]`.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct DohClientCred {
    /// Server name this credential authenticates to.
    pub server_name: String,
    /// Client certificate file.
    pub client_cert: String,
    /// Client private-key file.
    pub client_key: String,
    /// Optional root CA to validate the server with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_ca: Option<String>,
}

/// `[doh_client_x509_auth]` — client-certificate credentials for mutual-TLS DoH.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct DohClientX509Auth {
    /// The credential entries (`[[doh_client_x509_auth.creds]]`).
    #[serde(default)]
    pub creds: Vec<DohClientCred>,
}

/// One Anonymized-DNSCrypt route: a `server_name` reached via one or more relays (the 0x81 multi-hop).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct Route {
    /// The DNSCrypt server reached through the relays (`"*"` = any).
    pub server_name: String,
    /// Relay names (or stamps) forming the hop chain.
    #[serde(default)]
    pub via: Vec<String>,
}

/// `[anonymized_dns]` — Anonymized DNSCrypt relay routing (the 0x81 multi-hop the LAW keeps intact).
/// Scalars are declared BEFORE `routes` (the array-of-tables) so the serialized table is value-before-table (B2).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct AnonymizedDns {
    /// Send queries directly if a server is incompatible with relaying.
    #[serde(default)]
    pub skip_incompatible: bool,
    /// Fall back to direct cert retrieval when a relay can't fetch it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_cert_fallback: Option<bool>,
    /// The relay routes (`[[anonymized_dns.routes]]`).
    #[serde(default)]
    pub routes: Vec<Route>,
}

/// `[dns64]` — DNS64 NAT64-prefix synthesis (RFC 6147). Drives `resolver::set_dns64_prefixes`.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct Dns64 {
    /// NAT64 prefixes (e.g. `"64:ff9b::/96"`).
    #[serde(default)]
    pub prefix: Vec<String>,
    /// Resolvers used to discover the prefix automatically (RFC 7050).
    #[serde(default)]
    pub resolver: Vec<String>,
}

/// `[ip_encryption]` — client-IP encryption for the query log.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct IpEncryption {
    /// `"none"` (default), `"ipcrypt-deterministic"`, `"ipcrypt-nd"`, `"ipcrypt-ndx"`, `"ipcrypt-pfx"`.
    /// Open-ish set kept `String` (B8).
    #[serde(default = "def_none")]
    pub algorithm: String,
    /// The encryption key (empty = disabled).
    #[serde(default)]
    pub key: String,
}

impl Default for IpEncryption {
    fn default() -> Self {
        Self {
            algorithm: def_none(),
            key: String::new(),
        }
    }
}

/// `[monitoring_ui]` — the optional embedded monitoring web UI.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct MonitoringUi {
    /// Enable the monitoring UI.
    #[serde(default)]
    pub enabled: bool,
    /// Listen address for the UI. Default `"127.0.0.1:8080"`.
    #[serde(default = "def_mon_listen")]
    pub listen_address: String,
    /// Basic-auth username (empty = no auth). Default `"admin"`.
    #[serde(default = "def_admin")]
    pub username: String,
    /// Basic-auth password. Default `"changeme"`.
    #[serde(default = "def_changeme")]
    pub password: String,
    /// TLS certificate file (empty = HTTP).
    #[serde(default)]
    pub tls_certificate: String,
    /// TLS key file (empty = HTTP).
    #[serde(default)]
    pub tls_key: String,
    /// Show recent queries in the UI.
    #[serde(default = "def_true")]
    pub enable_query_log: bool,
    /// Privacy level: 0 all details · 1 anonymize client IPs (default) · 2 aggregate only.
    #[serde(default = "def_1")]
    pub privacy_level: i32,
    /// Max recent query-log entries kept in memory (default 100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_query_log_entries: Option<i32>,
    /// Max memory in MB for recent query logs (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mb: Option<i32>,
    /// Enable the Prometheus metrics endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus_enabled: Option<bool>,
    /// Path for the Prometheus metrics endpoint (default `/metrics`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prometheus_path: Option<String>,
}

impl Default for MonitoringUi {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: def_mon_listen(),
            username: def_admin(),
            password: def_changeme(),
            tls_certificate: String::new(),
            tls_key: String::new(),
            enable_query_log: def_true(),
            privacy_level: def_1(),
            max_query_log_entries: None,
            max_memory_mb: None,
            prometheus_enabled: None,
            prometheus_path: None,
        }
    }
}

/// `[static.<name>]` — an extra server pinned by its `sdns://` stamp.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, uniffi::Record)]
pub struct StaticServer {
    /// The `sdns://` DNS stamp for this server.
    pub stamp: String,
}

// =======================================================================================================
// serde default helpers — the SINGLE source of truth for each upstream default value (B3). Referenced
// by the `#[serde(default = "..")]` attributes AND the hand-written `impl Default`s, so the two never drift.
// =======================================================================================================

fn def_listen() -> Vec<String> {
    // STAGE 2 (Socio 2026-07-04): DNSCrypt listens on 127.0.0.1:5354, NOT :53. The high port needs no
    // privileged bind (the :53 bind failed on Android — "permission denied"), and it never clashes with
    // the pure-Rust tunnel loop's inline :53 interception (the tun loop answers system :53 packets via
    // torta_resolve; DNSCrypt's own local listener is the separate 5354 endpoint). The Socio's trick.
    vec!["127.0.0.1:5354".to_string()]
}
fn def_bootstrap() -> Vec<String> {
    vec!["9.9.9.11:53".to_string(), "8.8.8.8:53".to_string()]
}
fn def_netprobe() -> String {
    "9.9.9.9:53".to_string()
}
fn def_true() -> bool {
    true
}
fn def_250() -> i32 {
    250
}
fn def_5000() -> i32 {
    5000
}
fn def_30() -> i32 {
    30
}
fn def_10() -> i32 {
    10
}
fn def_7() -> i32 {
    7
}
fn def_1() -> i32 {
    1
}
fn def_240() -> i32 {
    240
}
fn def_60() -> i32 {
    60
}
fn def_4096() -> i32 {
    4096
}
fn def_2400() -> i32 {
    2400
}
fn def_86400() -> i32 {
    86400
}
fn def_600() -> i32 {
    600
}
fn def_tsv() -> String {
    "tsv".to_string()
}
fn def_none() -> String {
    "none".to_string()
}
/// Android 8+ requires `hinfo` for blocked queries (B7) — bake it into the default + export.
fn def_hinfo() -> Option<String> {
    Some("hinfo".to_string())
}
fn def_mon_listen() -> String {
    "127.0.0.1:8080".to_string()
}
fn def_admin() -> String {
    "admin".to_string()
}
fn def_changeme() -> String {
    "changeme".to_string()
}
/// The example's active 11-entry `fragments_blocked` list (cisco* + cleanbrowsing-* families).
fn def_fragments() -> Vec<String> {
    vec![
        "cisco".to_string(),
        "cisco-ipv6".to_string(),
        "cisco-familyshield".to_string(),
        "cisco-familyshield-ipv6".to_string(),
        "cisco-sandbox".to_string(),
        "cleanbrowsing-adult".to_string(),
        "cleanbrowsing-adult-ipv6".to_string(),
        "cleanbrowsing-family".to_string(),
        "cleanbrowsing-family-ipv6".to_string(),
        "cleanbrowsing-security".to_string(),
        "cleanbrowsing-security-ipv6".to_string(),
    ]
}

// =======================================================================================================
// K5 SLICE-2 — the TOML round-trip bridge, the typed config AUTHORITY, and the live-transport orchestrator.
// These are the surfaces the crate-root `#[uniffi::export]` front-door (`dnscrypt_config_*` in `lib.rs`)
// drives. The TOML is a COMPATIBILITY VIEW, never the authority (the Genesis "TOML-is-a-view" law): serde +
// toml do the round-trip, and `configure_from` fans out to the EXISTING resolver seams so no DNSCrypt
// transport capability regresses.
// =======================================================================================================

/// WHY a DNSCrypt-config bridge operation FAILED — the typed, UniFFI-bridged failure surface (the 4th
/// full-power UniFFI feature, the `CentauriError` model). Replaces a lossy empty-string /
/// `null` return with a `Result<_, ConfigError>` so Kotlin can `try/catch` an ACTIONABLE reason (a bad
/// imported TOML names WHY it was rejected; a serialize failure names the offending shape). `#[non_exhaustive]`
/// so a future failure mode is additive without breaking the Kotlin binding. UniFFI auto-derives `Display`
/// from the variant name + the `reason` field via `thiserror`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum ConfigError {
    /// `toml::from_str` rejected the imported `dnscrypt-proxy.toml` (a syntax error or a type mismatch).
    /// The inspect/validate path ([`from_toml`]) surfaces this so the UI can show the parse error; the
    /// boot/migration path ([`from_toml_or_default`]) fail-softs instead (a corrupt on-disk TOML must never
    /// brick the resolver — it degrades to the safe upstream baseline).
    #[error("toml parse failed: {reason}")]
    TomlParse { reason: String },

    /// `toml::to_string_pretty` failed to render the config (e.g. a values-after-tables ordering regression,
    /// B2). The struct is B2-safe by construction (all scalars/arrays precede all tables), so this is a guard
    /// against a FUTURE field-order edit, not an expected runtime path.
    #[error("toml serialize failed: {reason}")]
    TomlSerialize { reason: String },

    /// A panic inside the bridge — the `catch_unwind` firewall caught a bug and reports it as a typed error,
    /// never an abort across the FFI boundary. Never expected (the bridge is panic-free); kept so the
    /// contract is total.
    #[error("panic: {reason}")]
    Panic { reason: String },
}

/// The process-global typed config AUTHORITY — the source of truth Kotlin reads via [`get`] and writes via
/// [`set`] / `configure_from`(apply), so the UI never round-trips a TOML string. Lazily initialized to the
/// upstream [`DnscryptProxyConfig::default`] (B3-safe). A poisoned lock recovers in place (`into_inner`),
/// never panicking across the FFI boundary.
static CONFIG_AUTHORITY: OnceLock<Mutex<DnscryptProxyConfig>> = OnceLock::new();

fn authority() -> &'static Mutex<DnscryptProxyConfig> {
    CONFIG_AUTHORITY.get_or_init(|| Mutex::new(DnscryptProxyConfig::default()))
}

/// Read the held config authority (a CLONE — Kotlin owns the typed data class). A cold authority (never
/// written) returns the upstream [`DnscryptProxyConfig::default`].
pub fn get() -> DnscryptProxyConfig {
    authority()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Write the held config authority — the setter TWIN of [`get`]. Does NOT touch the live transport (that is
/// `configure_from`'s job), so Kotlin can STAGE typed edits and then COMMIT them in one `apply`.
pub fn set(cfg: DnscryptProxyConfig) {
    *authority().lock().unwrap_or_else(|e| e.into_inner()) = cfg;
}

/// Import a `dnscrypt-proxy.toml` into the typed config — the FULL-POWER typed path: a parse failure is a
/// typed [`ConfigError::TomlParse`] (Kotlin `try/catch`), never a silent default. Every ABSENT field lands
/// on its upstream `def_*` default (B3), so a PARTIAL TOML is faithfully completed, not zeroed.
pub fn from_toml(text: &str) -> Result<DnscryptProxyConfig, ConfigError> {
    toml::from_str::<DnscryptProxyConfig>(text).map_err(|e| ConfigError::TomlParse {
        reason: e.to_string(),
    })
}

/// Import a `dnscrypt-proxy.toml`, FAIL-SOFT to the upstream [`DnscryptProxyConfig::default`] — the
/// boot/migration path that must never brick: a corrupt or absent on-disk TOML degrades to a safe upstream
/// baseline (`require_nolog=true`, `cache=true`, `listen_addresses=['127.0.0.1:53']`, …), never an error.
/// This is the LAW's `import_dnscrypt_toml` contract.
pub fn from_toml_or_default(text: &str) -> DnscryptProxyConfig {
    from_toml(text).unwrap_or_default()
}

/// Export the typed config to a `dnscrypt-proxy.toml` — the COMPATIBILITY VIEW for the Go fallback + the
/// upstream ecosystem. `to_string_pretty` is B2-safe because the struct declares ALL values before ALL
/// tables. A (guarded-against) serialize failure is a typed [`ConfigError::TomlSerialize`].
pub fn to_toml(cfg: &DnscryptProxyConfig) -> Result<String, ConfigError> {
    toml::to_string_pretty(cfg).map_err(|e| ConfigError::TomlSerialize {
        reason: e.to_string(),
    })
}

// ---- W5 DurableTier persistence (RAMxNAND Opt-2 / #12) -------------------------------------------
//
// The config authority is a SELF-OWNED durable record (`"dnscrypt-config"`), framed by the shared
// [`crate::runtime_tier::DurableTier`] (MAGIC + version + SHA-256, atomic tmp+rename, 256KiB-bounded).
// Unlike the loose `dnscrypt-proxy.toml` — which stays a DERIVED compatibility VIEW the Kotlin readers
// (`ResolverRuntime` / `RotationManager` / `ProxyHelper` / `ModulesStarterHelper`) still parse — the
// DURABLE truth is this integrity-framed blob. [`persist`] runs ONLY on the control plane (a committed
// config edit / a boot seed); [`rehydrate`] runs ONCE at boot; [`materialize_toml`] regenerates the
// derived view Rust-side (atomic) so NO Kotlin `FileManager` write owns the config file. NEVER on the
// resolve hot path. The same self-owned-record posture as `resolver::rotation` / `dnscrypt_update`.

/// The DurableTier record name for the persisted config authority (sibling to `resolver-rotation`,
/// `dnscrypt-sync`, …). Traversal-free by construction (a bare basename).
const DURABLE_RECORD: &str = "dnscrypt-config";

/// Persist the CURRENT config authority to the app-private `dir` as the framed `"dnscrypt-config"`
/// DurableTier record (RAM heap → NAND atomic tmp+rename). The payload is the authority's TOML view
/// (`to_toml(&get())`) — the SAME lossless serialization the compatibility view uses, so the durable
/// blob is inspectable AND integrity-framed. Returns `true` on a durable write, `false` on ANY refusal
/// (a serialize failure, or an over-budget / IO-refused write). Best-effort: the in-memory authority is
/// untouched on a refusal (the charter's FAIL-SAFE invariant). Control-plane ONLY — never the resolve
/// path.
pub fn persist(dir: &std::path::Path) -> bool {
    let toml = match to_toml(&get()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let tier = crate::runtime_tier::DurableTier::with_dir(dir.to_path_buf(), DURABLE_RECORD);
    tier.write_through(toml.as_bytes()).is_ok()
}

/// Boot-rehydrate the config authority from the framed `"dnscrypt-config"` DurableTier record in `dir`.
/// A present + integrity-valid record is parsed FAIL-SOFT ([`from_toml_or_default`]) and installed via
/// [`set`], so a rebooted phone resumes its last committed config. Returns `true` IFF a record was
/// present; a cold / corrupt / tampered record leaves the authority at its upstream default and returns
/// `false` (the DurableTier integrity frame is the gate — never an error). Boot ONLY — never the resolve
/// path.
pub fn rehydrate(dir: &std::path::Path) -> bool {
    let tier = crate::runtime_tier::DurableTier::with_dir(dir.to_path_buf(), DURABLE_RECORD);
    match tier.rehydrate() {
        Some(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            set(from_toml_or_default(&text));
            true
        }
        None => false,
    }
}

/// Materialize the CURRENT config authority to a loose `dnscrypt-proxy.toml` at `path` — the DERIVED
/// compatibility VIEW the Kotlin readers still parse. Written Rust-side with an atomic tmp+rename
/// ([`write_toml_atomic`]) so a crash-before-rename never truncates the live view, and so NO Kotlin
/// `FileManager` write owns the config file. Returns `true` on a durable write, `false` on ANY refusal
/// (serialize / IO). Control-plane + boot ONLY.
pub fn materialize_toml(path: &std::path::Path) -> bool {
    let toml = match to_toml(&get()) {
        Ok(t) => t,
        Err(_) => return false,
    };
    write_toml_atomic(path, toml.as_bytes()).is_ok()
}

/// Atomic write of `bytes` to `path`: create the parent dir, write to a sibling `.<name>.tmp`, `fsync`,
/// then `rename` onto the final name (POSIX atomic replace on the same filesystem — the Android target).
/// A crash before the rename leaves the live file whole; the torn partial lands only in the `.tmp`. The
/// same tmp+rename discipline the shared DurableTier + the Kotlin `FileManager.atomicWriteLines` (#11)
/// use, applied to the loose compat view.
fn write_toml_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent();
    if let Some(p) = parent {
        std::fs::create_dir_all(p)?;
    }
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dnscrypt-proxy.toml".to_string());
    let tmp = match parent {
        Some(p) => p.join(format!(".{file_name}.tmp")),
        None => std::path::PathBuf::from(format!(".{file_name}.tmp")),
    };
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
    }
    // rename consumes the tmp; on a rename failure, best-effort-clean the orphan so no `.tmp` lingers.
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Minimal JSON string literal (escapes `\` and `"`) for building the `configure` upstream JSON without a
/// JSON dependency (the crate carries only `serde` + `toml`, not `serde_json`). `sdns://` stamps + server
/// ids are base64url / hostname-shaped, so escaping the two structural characters is sufficient + safe; the
/// resolver's own lenient `string_field` parser (mod.rs) unescapes them symmetrically.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Drive the LIVE resolver from the typed config — the **wiring point**. It fans out to the EXISTING resolver
/// seams (never re-implementing one), so NO transport capability regresses:
///
///   - **DNS64** (`[dns64].prefix`) → [`super::set_dns64_prefixes`] — the real independent global setter (an
///     empty prefix list turns DNS64 OFF, the byte-identical fast path). ALWAYS driven.
///   - **Server selection** (`[static.<name>].stamp` `sdns://` pins) → serialized to the SAME
///     `{"upstreams":[…]}` JSON [`super::configure`] already parses, then `configure(json, timeout, cache_cap)`
///     VERBATIM — the proven transport-build path (zero re-implementation: a bad pin skips just that upstream,
///     the `transports.is_empty() ⇒ None` posture is inherited). `timeout` + (`cache` × `cache_size`) size it.
///     With NO static pins it does NOT call `configure` (an empty set would tear down a source-configured
///     pool); the live transports are left untouched and the summary reports DNS64-only.
///
/// **Carried LOSSLESSLY, resolved by the existing source-load layer (GROUND_TRUTH: no Rust live-setter to
/// drive, so NOT fabricated):** the source-driven `server_names` (names reference source-loaded stamps the
/// core does not hold) and the `require_dnssec` / `require_nolog` / `require_nofilter` requirements (applied
/// when the source layer SELECTS which stamps to load). They round-trip in the authority for that layer to
/// read via [`get`].
///
/// **Never touched ⇒ cannot regress:** relay routing (`[anonymized_dns]`, the `dnscrypt::with_relays` seam),
/// the loopback listener (`listener::start_loopback`), and the auto-updater version-sync
/// (`dnscrypt_update`) — this fn calls NONE of their entrypoints; they keep their own proven seams.
///
/// Returns a human summary; ALWAYS `Some` (DNS64 is always driven) — never a spurious `None` that a caller
/// would read as total failure.
pub fn configure_from(cfg: &DnscryptProxyConfig) -> Option<String> {
    // 1) DNS64 — always driven (empty CSV ⇒ OFF). Independent global; never tears down the pool.
    let dns64_csv = cfg.dns64.prefix.join(",");
    super::set_dns64_prefixes(&dns64_csv);
    let dns64_n = cfg.dns64.prefix.len();

    // 2) Server selection — build the upstream JSON from the static `sdns://` pins (a blank stamp is
    //    skipped). With NO usable pins, DON'T call `configure` (an empty set would discard a source-built
    //    pool); leave the live transports untouched and report DNS64-only.
    let upstreams: Vec<String> = cfg
        .static_servers
        .iter()
        .filter(|(_, s)| !s.stamp.trim().is_empty())
        .map(|(name, s)| {
            format!(
                "{{\"id\":{},\"transport\":\"dnscrypt\",\"stamp\":{}}}",
                json_string(name),
                json_string(&s.stamp)
            )
        })
        .collect();

    let timeout = if cfg.timeout > 0 {
        cfg.timeout as u64
    } else {
        5000
    };
    let cache_cap = if cfg.cache && cfg.cache_size > 0 {
        cfg.cache_size as usize
    } else {
        1
    };

    if upstreams.is_empty() {
        return Some(format!(
            "dns64={dns64_n} static_upstreams=0 (source-driven selection unchanged)"
        ));
    }

    let json = format!("{{\"upstreams\":[{}]}}", upstreams.join(","));
    match super::configure(&json, timeout, cache_cap) {
        Some(summary) => Some(format!("dns64={dns64_n} {summary}")),
        None => Some(format!(
            "dns64={dns64_n} static_upstreams={} usable=0",
            upstreams.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-written Default must land on UPSTREAM values, never type-zeros (B3).
    #[test]
    fn default_lands_on_upstream_values() {
        let c = DnscryptProxyConfig::default();
        assert_eq!(c.listen_addresses, vec!["127.0.0.1:5354".to_string()]);
        assert_eq!(c.max_clients, 250);
        assert!(c.require_nolog);
        assert!(c.require_nofilter);
        assert!(c.ignore_system_dns);
        assert!(c.cache);
        assert_eq!(c.cache_size, 4096);
        assert_eq!(c.netprobe_timeout, 60);
        assert_eq!(c.blocked_query_response.as_deref(), Some("hinfo"));
        assert_eq!(
            c.bootstrap_resolvers,
            vec!["9.9.9.11:53".to_string(), "8.8.8.8:53".to_string()]
        );
        assert_eq!(c.broken_implementations.fragments_blocked.len(), 11);
        assert_eq!(c.query_log.format, "tsv");
        assert_eq!(c.ip_encryption.algorithm, "none");
        assert_eq!(c.monitoring_ui.listen_address, "127.0.0.1:8080");
    }

    /// An EMPTY TOML must deserialize to the same upstream baseline (every field has a serde default, B3).
    #[test]
    fn empty_toml_matches_default() {
        let from_empty: DnscryptProxyConfig =
            toml::from_str("").expect("empty TOML is all-defaults");
        let d = DnscryptProxyConfig::default();
        assert_eq!(from_empty.listen_addresses, d.listen_addresses);
        assert_eq!(from_empty.cache, d.cache);
        assert_eq!(from_empty.require_nolog, d.require_nolog);
        assert_eq!(from_empty.blocked_query_response, d.blocked_query_response);
        assert_eq!(
            from_empty.broken_implementations.fragments_blocked,
            d.broken_implementations.fragments_blocked
        );
    }

    /// A PARTIAL import must keep the security-relevant ★ defaults, not zero them (the B3 trap).
    #[test]
    fn partial_import_preserves_security_defaults() {
        let partial = "server_names = ['my-server']\nrequire_dnssec = true\n";
        let c: DnscryptProxyConfig = toml::from_str(partial).expect("partial parses");
        assert_eq!(c.server_names, vec!["my-server".to_string()]);
        assert!(c.require_dnssec);
        // The fields the partial did NOT set must remain upstream, not type-zero:
        assert!(
            c.require_nolog,
            "require_nolog must stay true on partial import"
        );
        assert!(c.cache, "cache must stay true on partial import");
        assert_eq!(c.timeout, 5000, "timeout must stay 5000 on partial import");
        assert_eq!(c.listen_addresses, vec!["127.0.0.1:5354".to_string()]);
    }

    /// W5 DurableTier (#12 slice 1): the config authority survives a RAM→NAND→RAM round trip, the derived
    /// TOML view materializes atomically (no orphan tmp), and a COLD dir rehydrates FALSE leaving the
    /// authority untouched (fail-safe). This is the ONLY test that mutates the process-global authority
    /// via `set`/`get`; it owns the global for its duration (no sibling test touches it).
    #[test]
    fn durable_persist_rehydrate_materialize_round_trip() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-w5-dnscfg-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);

        // 1) Stage a representative NON-default config into the authority + persist to the DurableTier.
        //    Socio PRIVACY LAW: the proxy uses an RFC-5737 doc address, never a real resolver.
        let staged = DnscryptProxyConfig {
            server_names: vec!["durable-server".to_string()],
            require_dnssec: true,
            force_tcp: true,
            proxy: Some("socks5://198.51.100.9:9050".to_string()),
            ..Default::default()
        };
        set(staged);
        assert!(persist(&dir), "persist writes a durable record");

        // 2) Clobber the authority back to default (simulate a fresh process), then rehydrate.
        set(DnscryptProxyConfig::default());
        assert!(
            !get().require_dnssec,
            "authority is back at default before rehydrate"
        );
        assert!(rehydrate(&dir), "rehydrate finds the durable record");

        // 3) The rehydrated authority equals what we staged (survives RAM→NAND→RAM), and the fields we
        //    did NOT stage stay upstream-default (B3 — never zeroed by a partial durable blob).
        let back = get();
        assert_eq!(back.server_names, vec!["durable-server".to_string()]);
        assert!(back.require_dnssec, "require_dnssec survives the durable round trip");
        assert!(back.force_tcp, "force_tcp survives");
        assert_eq!(back.proxy.as_deref(), Some("socks5://198.51.100.9:9050"));
        assert!(back.require_nolog, "unstated field stays upstream-default (true)");
        assert!(back.cache, "unstated field stays upstream-default (true)");

        // 4) materialize_toml writes the loose compat view atomically; it re-imports equal, no orphan tmp.
        let toml_path = dir.join("dnscrypt-proxy.toml");
        assert!(materialize_toml(&toml_path), "materialize writes the derived toml");
        let on_disk = std::fs::read_to_string(&toml_path).unwrap();
        let reparsed = from_toml_or_default(&on_disk);
        assert!(reparsed.require_dnssec, "materialized toml carries require_dnssec");
        assert_eq!(reparsed.proxy.as_deref(), Some("socks5://198.51.100.9:9050"));
        assert!(
            !dir.join(".dnscrypt-proxy.toml.tmp").exists(),
            "no orphan tmp lingers after an atomic materialize"
        );

        // 5) A COLD dir rehydrates FALSE and leaves the authority untouched (fail-safe cold start).
        let cold = std::env::temp_dir().join(format!("torta-w5-dnscfg-cold-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&cold);
        assert!(!rehydrate(&cold), "an absent record rehydrates false (cold)");
        assert!(
            get().require_dnssec,
            "a cold rehydrate leaves the live authority untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&cold);
    }

    /// Full round-trip: a representative config exports to TOML (values-before-tables, B2) and re-imports
    /// equal on the fields we assert (relay routing + DNS64 + loopback survive the TOML move).
    #[test]
    fn round_trip_preserves_capabilities() {
        // Struct-literal (not `let mut = default(); c.f = ..`) — clippy::field_reassign_with_default clean.
        let c = DnscryptProxyConfig {
            server_names: vec!["server-1".to_string()],
            dns64: Dns64 {
                prefix: vec!["64:ff9b::/96".to_string()],
                ..Default::default()
            },
            local_doh: LocalDoh {
                listen_addresses: vec!["127.0.0.1:3000".to_string()],
                ..Default::default()
            },
            anonymized_dns: AnonymizedDns {
                routes: vec![Route {
                    server_name: "server-1".to_string(),
                    via: vec!["relay-a".to_string(), "relay-b".to_string()],
                }],
                ..Default::default()
            },
            sources: HashMap::from([(
                "public-resolvers".to_string(),
                Source {
                    urls: vec!["https://example/resolvers.md".to_string()],
                    cache_file: "public-resolvers.md".to_string(),
                    minisign_key: "RWQ...".to_string(),
                    refresh_delay: Some(72),
                    prefix: String::new(),
                    cache_ttl: None,
                },
            )]),
            ..Default::default()
        };

        // B2: this must NOT error with "values must be emitted before tables".
        let toml_text = toml::to_string_pretty(&c).expect("serialize (values before tables)");
        let back: DnscryptProxyConfig = toml::from_str(&toml_text).expect("re-import");

        assert_eq!(back.server_names, c.server_names);
        assert_eq!(back.dns64.prefix, c.dns64.prefix);
        assert_eq!(
            back.local_doh.listen_addresses,
            c.local_doh.listen_addresses
        );
        assert_eq!(back.anonymized_dns.routes.len(), 1);
        assert_eq!(back.anonymized_dns.routes[0].via.len(), 2);
        assert_eq!(
            back.sources
                .get("public-resolvers")
                .map(|s| s.refresh_delay),
            Some(Some(72))
        );
    }

    /// The bridge `to_toml → from_toml` round-trips through the SAME serde path the UniFFI export drives,
    /// preserving the must-not-regress capabilities (relay routing + DNS64 + loopback) lossless. Pure: no
    /// process globals touched (green in every resolver-mounting binary).
    #[test]
    fn bridge_to_toml_from_toml_round_trips() {
        let c = DnscryptProxyConfig {
            require_dnssec: true,
            dns64: Dns64 {
                prefix: vec!["64:ff9b::/96".to_string()],
                ..Default::default()
            },
            local_doh: LocalDoh {
                listen_addresses: vec!["127.0.0.1:3000".to_string()],
                ..Default::default()
            },
            anonymized_dns: AnonymizedDns {
                routes: vec![Route {
                    server_name: "srv".to_string(),
                    via: vec!["relay-a".to_string()],
                }],
                ..Default::default()
            },
            static_servers: HashMap::from([(
                "pin-1".to_string(),
                StaticServer {
                    stamp: "sdns://AgcAAAAAAAAAAAA".to_string(),
                },
            )]),
            ..Default::default()
        };

        let text = to_toml(&c).expect("export (B2 values-before-tables)");
        let back = from_toml(&text).expect("re-import the exported view");

        assert!(back.require_dnssec);
        assert_eq!(back.dns64.prefix, c.dns64.prefix);
        assert_eq!(
            back.local_doh.listen_addresses,
            c.local_doh.listen_addresses
        );
        assert_eq!(back.anonymized_dns.routes.len(), 1);
        assert_eq!(
            back.anonymized_dns.routes[0].via,
            vec!["relay-a".to_string()]
        );
        assert_eq!(
            back.static_servers.get("pin-1").map(|s| s.stamp.clone()),
            Some("sdns://AgcAAAAAAAAAAAA".to_string())
        );
        // Untouched security defaults stay upstream through the round-trip (B3).
        assert!(back.require_nolog);
        assert!(back.cache);
    }

    /// Fail-soft import: a corrupt/non-TOML blob degrades to the upstream Default (the boot path that must
    /// never brick), while the typed `from_toml` reports WHY. Pure: no globals.
    #[test]
    fn from_toml_or_default_fail_softs_but_typed_reports() {
        let garbage = "this is = = not [valid toml ][[";
        let cfg = from_toml_or_default(garbage);
        // Degraded to the safe upstream baseline, not a half-parsed / zeroed config.
        assert_eq!(cfg.listen_addresses, vec!["127.0.0.1:5354".to_string()]);
        assert!(cfg.require_nolog);
        assert!(cfg.cache);
        // The typed path names the failure instead of swallowing it.
        match from_toml(garbage) {
            Err(ConfigError::TomlParse { reason }) => assert!(!reason.is_empty()),
            other => panic!("expected a typed TomlParse error, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod real_example_tests {
    //! ⚪ EXECUTOR 3 — the TRIPLE-DUTY proven against a GENUINE upstream `dnscrypt-proxy.toml`.
    //!
    //! `super::tests` (Executor 1) proves the contract on hand-crafted snippets; this module raises the
    //! bar to the REAL upstream file. Four genuinely-tests-it proofs, matching the wave's (a)–(d):
    //!
    //! - **(a)** the upstream `example-dnscrypt-proxy.toml` ACTIVE field set imports to a fully-populated
    //!   config (every shipped value asserted, + the absent fields land on their `def_*` upstream default);
    //! - **(b)** every must-not-regress capability table — relay routing (`anonymized_dns.routes`, the 0x81
    //!   multi-hop) · DNS64 · the loopback `local_doh` · `[schedules]` · `[static]` pins · DoH client x509
    //!   creds — imports AND survives import→export→re-import LOSSLESS through the `to_toml`/`from_toml`
    //!   bridge the UniFFI front-door drives (the LAW: nothing regresses in the TOML→Rust move);
    //!   round-trip equality is asserted BY-KEY / BY-FIELD (order-independent — the config holds `HashMap`s,
    //!   whose iteration order is non-deterministic, so a serialized-string comparison would flake);
    //! - **(c)** `Default` is sane — it equals the imported upstream baseline (the example ships defaults);
    //! - **(d)** a malformed TOML fail-softs to the safe upstream `Default` with NO panic, while the typed
    //!   `from_toml` NAMES the failure.
    use super::*;

    /// A genuine `dnscrypt-proxy.toml` as upstream ships it: the ACTIVE (uncommented) field set of
    /// `dnscrypt-proxy-master/dnscrypt-proxy/example-dnscrypt-proxy.toml`, verbatim values. The capability
    /// tables (`[anonymized_dns].routes`, `[dns64]`, `[schedules]`, `[static]`, …) are left at their shipped
    /// (commented ⇒ default) state — exactly what an out-of-the-box install parses.
    const REAL_EXAMPLE_TOML: &str = r#"
listen_addresses = ['127.0.0.1:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
odoh_servers = false
require_dnssec = false
require_nolog = true
require_nofilter = true
disabled_server_names = []
force_tcp = false
http3 = false
http3_probe = false
timeout = 5000
keepalive = 30
log_files_max_size = 10
log_files_max_age = 7
log_files_max_backups = 1
cert_refresh_delay = 240
bootstrap_resolvers = ['9.9.9.11:53', '8.8.8.8:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'
block_ipv6 = false
block_unqualified = true
block_undelegated = true
reject_ttl = 10
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

[captive_portals]

[local_doh]

[query_log]
format = 'tsv'

[nx_log]
format = 'tsv'

[blocked_names]

[blocked_ips]

[allowed_names]

[allowed_ips]

[schedules]

[sources]

[sources.public-resolvers]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
  'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md'
]
cache_file = 'public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

[sources.relays]
urls = [
  'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
  'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
  'https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/relays.md'
]
cache_file = 'relays.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

[broken_implementations]
fragments_blocked = [
  'cisco',
  'cisco-ipv6',
  'cisco-familyshield',
  'cisco-familyshield-ipv6',
  'cisco-sandbox',
  'cleanbrowsing-adult',
  'cleanbrowsing-adult-ipv6',
  'cleanbrowsing-family',
  'cleanbrowsing-family-ipv6',
  'cleanbrowsing-security',
  'cleanbrowsing-security-ipv6',
]

[doh_client_x509_auth]

[anonymized_dns]
skip_incompatible = false

[dns64]

[ip_encryption]
algorithm = "none"
key = ""

[monitoring_ui]
enabled = false
listen_address = "127.0.0.1:8080"
username = "admin"
password = "changeme"
tls_certificate = ""
tls_key = ""
enable_query_log = true
privacy_level = 1

[static]
"#;

    /// The same genuine file, with every must-not-regress capability table ARMED using upstream's OWN
    /// documented example values (the commented `!!! THESE ARE JUST EXAMPLES !!!` blocks, uncommented).
    /// Exercises the HARDEST mappings: array-of-inline-tables (`routes`, `creds`), map-of-tables
    /// (`schedules`, `static`), the DNS64 prefix list, and the loopback `local_doh` listener.
    const ARMED_EXAMPLE_TOML: &str = r#"
listen_addresses = ['127.0.0.1:53']
max_clients = 250
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
odoh_servers = false
require_dnssec = true
require_nolog = true
require_nofilter = true
force_tcp = false
timeout = 5000
keepalive = 30
bootstrap_resolvers = ['9.9.9.11:53', '8.8.8.8:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'
block_unqualified = true
block_undelegated = true
reject_ttl = 10
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

[captive_portals]
map_file = 'example-captive-portals.txt'

[local_doh]
listen_addresses = ['127.0.0.1:3000']
path = '/dns-query'

[query_log]
format = 'tsv'

[nx_log]
format = 'tsv'

[schedules.time-to-sleep]
mon = [{ after = '21:00', before = '7:00' }]
fri = [{ after = '23:00', before = '7:00' }]

[sources.public-resolvers]
urls = ['https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
cache_file = 'public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

[broken_implementations]
fragments_blocked = ['cisco', 'cisco-ipv6']

[doh_client_x509_auth]
creds = [
  { server_name = '*', client_cert = 'client.crt', client_key = 'client.key' },
]

[anonymized_dns]
skip_incompatible = false
direct_cert_fallback = false
routes = [
  { server_name = 'example-server-1', via = ['anon-example-1', 'anon-example-2'] },
  { server_name = 'example-server-2', via = ['sdns://gRIxMzcuNzQuMjIzLjIzNDo0NDM'] },
]

[dns64]
prefix = ['64:ff9b::/96']
resolver = ['[2606:4700:4700::64]:53', '[2001:4860:4860::64]:53']

[ip_encryption]
algorithm = "none"
key = ""

[static.myserver]
stamp = 'sdns://AQcAAAAAAAAAAAAQMi5kbnNjcnlwdC1jZXJ0Lg'
"#;

    /// Order-independent round-trip equality on the broad common surface (scalars, the source list, DNS64,
    /// the relay routes, the loopback listener, the log/monitoring tables). Maps are compared BY KEY and
    /// `Vec`s element-wise so a non-deterministic `HashMap` iteration order can never flake the assert.
    /// `TimeRange`/`Route`/`StaticServer`/`DohClientCred` carry no `PartialEq`, so leaf fields are compared.
    /// `pub(super)` so the `shipped_asset` module can hold the SHIPPED file to exactly this
    /// standard instead of a weaker hand-rolled comparison (checkpoint 100).
    pub(super) fn assert_round_trip_eq(a: &DnscryptProxyConfig, b: &DnscryptProxyConfig) {
        // scalars + Vec<String> (order-preserving)
        assert_eq!(a.listen_addresses, b.listen_addresses);
        assert_eq!(a.server_names, b.server_names);
        assert_eq!(a.max_clients, b.max_clients);
        assert_eq!(a.ipv4_servers, b.ipv4_servers);
        assert_eq!(a.ipv6_servers, b.ipv6_servers);
        assert_eq!(a.dnscrypt_servers, b.dnscrypt_servers);
        assert_eq!(a.doh_servers, b.doh_servers);
        assert_eq!(a.require_dnssec, b.require_dnssec);
        assert_eq!(a.require_nolog, b.require_nolog);
        assert_eq!(a.require_nofilter, b.require_nofilter);
        assert_eq!(a.timeout, b.timeout);
        assert_eq!(a.keepalive, b.keepalive);
        assert_eq!(a.cache, b.cache);
        assert_eq!(a.cache_size, b.cache_size);
        assert_eq!(a.cache_neg_max_ttl, b.cache_neg_max_ttl);
        assert_eq!(a.bootstrap_resolvers, b.bootstrap_resolvers);
        assert_eq!(a.ignore_system_dns, b.ignore_system_dns);
        assert_eq!(a.netprobe_timeout, b.netprobe_timeout);
        assert_eq!(a.netprobe_address, b.netprobe_address);
        assert_eq!(a.blocked_query_response, b.blocked_query_response);

        // tables with scalar leaves
        assert_eq!(a.query_log.format, b.query_log.format);
        assert_eq!(a.nx_log.format, b.nx_log.format);
        assert_eq!(a.ip_encryption.algorithm, b.ip_encryption.algorithm);
        assert_eq!(a.ip_encryption.key, b.ip_encryption.key);
        assert_eq!(
            a.monitoring_ui.listen_address,
            b.monitoring_ui.listen_address
        );
        assert_eq!(a.monitoring_ui.privacy_level, b.monitoring_ui.privacy_level);
        assert_eq!(
            a.monitoring_ui.enable_query_log,
            b.monitoring_ui.enable_query_log
        );
        assert_eq!(
            a.broken_implementations.fragments_blocked,
            b.broken_implementations.fragments_blocked
        );
        assert_eq!(a.captive_portals.map_file, b.captive_portals.map_file);

        // loopback listener (must-not-regress)
        assert_eq!(a.local_doh.listen_addresses, b.local_doh.listen_addresses);
        assert_eq!(a.local_doh.path, b.local_doh.path);

        // DNS64 (must-not-regress)
        assert_eq!(a.dns64.prefix, b.dns64.prefix);
        assert_eq!(a.dns64.resolver, b.dns64.resolver);

        // relay routing — the 0x81 multi-hop (must-not-regress); Route has no PartialEq → leaf compare
        assert_eq!(
            a.anonymized_dns.skip_incompatible,
            b.anonymized_dns.skip_incompatible
        );
        assert_eq!(
            a.anonymized_dns.direct_cert_fallback,
            b.anonymized_dns.direct_cert_fallback
        );
        assert_eq!(a.anonymized_dns.routes.len(), b.anonymized_dns.routes.len());
        for (ra, rb) in a.anonymized_dns.routes.iter().zip(&b.anonymized_dns.routes) {
            assert_eq!(ra.server_name, rb.server_name);
            assert_eq!(ra.via, rb.via);
        }

        // the source list (version-sync) — map-of-tables, BY KEY (order-independent)
        assert_eq!(a.sources.len(), b.sources.len());
        for (k, sa) in &a.sources {
            let sb = b
                .sources
                .get(k)
                .unwrap_or_else(|| panic!("source {k} lost on round-trip"));
            assert_eq!(sa.urls, sb.urls);
            assert_eq!(sa.cache_file, sb.cache_file);
            assert_eq!(sa.minisign_key, sb.minisign_key);
            assert_eq!(sa.refresh_delay, sb.refresh_delay);
            assert_eq!(sa.prefix, sb.prefix);
            assert_eq!(sa.cache_ttl, sb.cache_ttl);
        }
    }

    /// (a) The upstream example's ACTIVE field set imports to a fully-populated config — every shipped
    /// value, plus the absent `blocked_query_response` landing on its `hinfo` upstream default (B7).
    #[test]
    fn real_example_imports_active_fields() {
        let c = from_toml(REAL_EXAMPLE_TOML).expect("the real upstream example must import");

        // top-level scalars / arrays (shipped active values)
        assert_eq!(c.listen_addresses, vec!["127.0.0.1:53".to_string()]);
        assert_eq!(c.max_clients, 250);
        assert!(c.ipv4_servers);
        assert!(!c.ipv6_servers);
        assert!(c.dnscrypt_servers);
        assert!(c.doh_servers);
        assert!(!c.odoh_servers);
        assert!(!c.require_dnssec);
        assert!(c.require_nolog);
        assert!(c.require_nofilter);
        assert!(c.disabled_server_names.is_empty());
        assert!(!c.force_tcp);
        assert!(!c.http3);
        assert_eq!(c.timeout, 5000);
        assert_eq!(c.keepalive, 30);
        assert_eq!(c.log_files_max_size, 10);
        assert_eq!(c.log_files_max_age, 7);
        assert_eq!(c.log_files_max_backups, 1);
        assert_eq!(c.cert_refresh_delay, 240);
        assert_eq!(
            c.bootstrap_resolvers,
            vec!["9.9.9.11:53".to_string(), "8.8.8.8:53".to_string()]
        );
        assert!(c.ignore_system_dns);
        assert_eq!(c.netprobe_timeout, 60);
        assert_eq!(c.netprobe_address, "9.9.9.9:53");
        assert!(!c.block_ipv6);
        assert!(c.block_unqualified);
        assert!(c.block_undelegated);
        assert_eq!(c.reject_ttl, 10);
        assert!(c.cache);
        assert_eq!(c.cache_size, 4096);
        assert_eq!(c.cache_min_ttl, 2400);
        assert_eq!(c.cache_max_ttl, 86400);
        assert_eq!(c.cache_neg_min_ttl, 60);
        assert_eq!(c.cache_neg_max_ttl, 600);

        // a field the real file does NOT set lands on its upstream default, not a type-zero (B3/B7)
        assert_eq!(c.blocked_query_response.as_deref(), Some("hinfo"));

        // active tables
        assert_eq!(c.query_log.format, "tsv");
        assert!(c.query_log.file.is_none());
        assert!(c.query_log.ignored_qtypes.is_empty());
        assert_eq!(c.nx_log.format, "tsv");
        assert_eq!(c.ip_encryption.algorithm, "none");
        assert_eq!(c.ip_encryption.key, "");
        assert!(!c.monitoring_ui.enabled);
        assert_eq!(c.monitoring_ui.listen_address, "127.0.0.1:8080");
        assert_eq!(c.monitoring_ui.username, "admin");
        assert_eq!(c.monitoring_ui.password, "changeme");
        assert!(c.monitoring_ui.enable_query_log);
        assert_eq!(c.monitoring_ui.privacy_level, 1);
        assert!(c.monitoring_ui.max_query_log_entries.is_none());
        assert!(c.monitoring_ui.prometheus_enabled.is_none());

        // the active broken-implementations list (11 entries, the cisco* + cleanbrowsing-* families)
        assert_eq!(c.broken_implementations.fragments_blocked.len(), 11);
        assert!(c
            .broken_implementations
            .fragments_blocked
            .contains(&"cisco".to_string()));
        assert!(c
            .broken_implementations
            .fragments_blocked
            .contains(&"cleanbrowsing-security-ipv6".to_string()));

        // the two active [sources.*] tables (the public-resolvers list + the 0x81 relays.md source)
        assert_eq!(c.sources.len(), 2);
        let pr = c
            .sources
            .get("public-resolvers")
            .expect("public-resolvers source");
        assert_eq!(pr.urls.len(), 3);
        assert_eq!(pr.cache_file, "public-resolvers.md");
        assert!(pr.minisign_key.starts_with("RWQf6"));
        assert_eq!(pr.refresh_delay, Some(73));
        assert_eq!(pr.prefix, "");
        assert!(pr.cache_ttl.is_none());
        let relays = c.sources.get("relays").expect("relays source");
        assert_eq!(relays.cache_file, "relays.md");
        assert_eq!(relays.urls.len(), 3);

        // anonymized_dns header present but routes shipped-commented ⇒ default
        assert!(!c.anonymized_dns.skip_incompatible);
        assert!(c.anonymized_dns.routes.is_empty());
        assert!(c.anonymized_dns.direct_cert_fallback.is_none());

        // the shipped-commented capability tables fall to their defaults (not fabricated)
        assert!(c.dns64.prefix.is_empty());
        assert!(c.dns64.resolver.is_empty());
        assert!(c.static_servers.is_empty());
        assert!(c.schedules.is_empty());
        assert!(c.local_doh.listen_addresses.is_empty());
        assert!(c.local_doh.path.is_none());
        assert!(c.captive_portals.map_file.is_none());
        assert!(c.doh_client_x509_auth.creds.is_empty());
        assert!(c.blocked_names.blocked_names_file.is_none());
    }

    /// (b) Every must-not-regress capability table imports when armed with upstream's own example values:
    /// relay routing (the 0x81 multi-hop), DNS64, the loopback listener, schedules, static pins, x509 creds.
    #[test]
    fn armed_example_imports_capability_tables() {
        let c = from_toml(ARMED_EXAMPLE_TOML).expect("the armed example must import");

        // relay routing — anonymized DNS 0x81 multi-hop (the LAW says this must stay intact)
        assert_eq!(c.anonymized_dns.routes.len(), 2);
        assert_eq!(c.anonymized_dns.routes[0].server_name, "example-server-1");
        assert_eq!(
            c.anonymized_dns.routes[0].via,
            vec!["anon-example-1".to_string(), "anon-example-2".to_string()]
        );
        assert_eq!(c.anonymized_dns.routes[1].server_name, "example-server-2");
        assert_eq!(
            c.anonymized_dns.routes[1].via,
            vec!["sdns://gRIxMzcuNzQuMjIzLjIzNDo0NDM".to_string()]
        );
        assert_eq!(c.anonymized_dns.direct_cert_fallback, Some(false));

        // DNS64 NAT64-prefix synthesis (must-not-regress)
        assert_eq!(c.dns64.prefix, vec!["64:ff9b::/96".to_string()]);
        assert_eq!(c.dns64.resolver.len(), 2);

        // loopback listener (must-not-regress)
        assert_eq!(
            c.local_doh.listen_addresses,
            vec!["127.0.0.1:3000".to_string()]
        );
        assert_eq!(c.local_doh.path.as_deref(), Some("/dns-query"));

        // [schedules.<name>] — map-of-tables + array-of-inline-tables (the hardest mapping)
        assert_eq!(c.schedules.len(), 1);
        let sched = c
            .schedules
            .get("time-to-sleep")
            .expect("time-to-sleep schedule");
        assert_eq!(sched.mon.len(), 1);
        assert_eq!(sched.mon[0].after, "21:00");
        assert_eq!(sched.mon[0].before, "7:00");
        assert_eq!(sched.fri.len(), 1);
        assert!(sched.tue.is_empty());

        // [static.<name>] pin — map-of-tables
        assert_eq!(c.static_servers.len(), 1);
        let pin = c
            .static_servers
            .get("myserver")
            .expect("myserver static pin");
        assert!(pin.stamp.starts_with("sdns://"));

        // [doh_client_x509_auth].creds — array-of-inline-tables + per-entry Option
        assert_eq!(c.doh_client_x509_auth.creds.len(), 1);
        assert_eq!(c.doh_client_x509_auth.creds[0].server_name, "*");
        assert_eq!(c.doh_client_x509_auth.creds[0].client_cert, "client.crt");
        assert!(c.doh_client_x509_auth.creds[0].root_ca.is_none());

        // captive portals
        assert_eq!(
            c.captive_portals.map_file.as_deref(),
            Some("example-captive-portals.txt")
        );
    }

    /// (b) import → export → re-import preserves the real upstream baseline LOSSLESS through the bridge,
    /// and the exported view is a genuine `dnscrypt-proxy.toml` (it carries the live tables, not a stub).
    #[test]
    fn real_example_round_trips_through_the_bridge() {
        let cfg = from_toml(REAL_EXAMPLE_TOML).expect("real example imports");
        let exported = to_toml(&cfg).expect("export is B2-safe (all values before all tables)");
        let back = from_toml(&exported).expect("the exported view re-imports");

        assert_round_trip_eq(&cfg, &back);

        // absent capability tables stay absent across the round-trip (nothing fabricated on export)
        assert!(back.dns64.prefix.is_empty());
        assert!(back.anonymized_dns.routes.is_empty());
        assert!(back.static_servers.is_empty());
        assert!(back.schedules.is_empty());

        // the Go-fallback compatibility view is a usable TOML carrying the live tables
        assert!(exported.contains("[sources.public-resolvers]"));
        assert!(exported.contains("fragments_blocked"));
    }

    /// (b) the must-not-regress capability tables survive import → export → re-import LOSSLESS. The
    /// `to_toml` here is the real B2 stress: it serializes routes (array-of-tables), DNS64, the map-of-
    /// struct-of-arrays `[schedules]` (the deepest serialize path), `[static]`, and the x509 creds.
    #[test]
    fn armed_example_round_trips_capabilities_lossless() {
        let cfg = from_toml(ARMED_EXAMPLE_TOML).expect("armed example imports");
        let exported = to_toml(&cfg).expect("export armed config (B2-safe, incl. [schedules])");
        let back = from_toml(&exported).expect("the armed exported view re-imports");

        // the broad common surface (routes, dns64, local_doh, sources) survives equal
        assert_round_trip_eq(&cfg, &back);

        // [schedules] (map of struct-of-arrays) survives — by key, TimeRange compared field-wise
        assert_eq!(back.schedules.len(), 1);
        let sched = back
            .schedules
            .get("time-to-sleep")
            .expect("schedule survived");
        assert_eq!(sched.mon.len(), 1);
        assert_eq!(sched.mon[0].after, "21:00");
        assert_eq!(sched.mon[0].before, "7:00");
        assert_eq!(sched.fri.len(), 1);

        // [static] pin (map) survives
        assert_eq!(back.static_servers.len(), 1);
        assert!(back
            .static_servers
            .get("myserver")
            .expect("static pin survived")
            .stamp
            .starts_with("sdns://"));

        // DoH client x509 creds (array-of-tables) survive
        assert_eq!(back.doh_client_x509_auth.creds.len(), 1);
        assert_eq!(back.doh_client_x509_auth.creds[0].server_name, "*");
        assert!(back.doh_client_x509_auth.creds[0].root_ca.is_none());
    }

    /// (c) `Default` is sane — it equals the imported upstream baseline (the example ships upstream
    /// defaults), proving the hand-written `impl Default` (B3) is the real upstream config, not type-zeros.
    #[test]
    fn default_is_sane_and_matches_upstream_baseline() {
        let d = DnscryptProxyConfig::default();
        let upstream = from_toml(REAL_EXAMPLE_TOML).expect("real example imports");

        // STAGE 2: the sovereign default listens on 127.0.0.1:5354 (the high-port trick — no privileged
        // bind, no clash with the pure-Rust tunnel's inline :53 interception), whereas the upstream
        // dnscrypt-proxy example uses :53. This is a DELIBERATE divergence, not a regression.
        assert_eq!(d.listen_addresses, vec!["127.0.0.1:5354".to_string()]);
        assert_eq!(upstream.listen_addresses, vec!["127.0.0.1:53".to_string()]);
        assert_eq!(d.max_clients, upstream.max_clients);
        assert_eq!(d.ipv4_servers, upstream.ipv4_servers);
        assert_eq!(d.require_nolog, upstream.require_nolog);
        assert_eq!(d.require_nofilter, upstream.require_nofilter);
        assert_eq!(d.cache, upstream.cache);
        assert_eq!(d.cache_size, upstream.cache_size);
        assert_eq!(d.timeout, upstream.timeout);
        assert_eq!(d.netprobe_timeout, upstream.netprobe_timeout);
        assert_eq!(d.bootstrap_resolvers, upstream.bootstrap_resolvers);
        assert_eq!(d.blocked_query_response, upstream.blocked_query_response);
        assert_eq!(d.ip_encryption.algorithm, upstream.ip_encryption.algorithm);
        assert_eq!(
            d.monitoring_ui.listen_address,
            upstream.monitoring_ui.listen_address
        );
        assert_eq!(
            d.broken_implementations.fragments_blocked,
            upstream.broken_implementations.fragments_blocked
        );
        // and the sanity floor: the security-relevant defaults are the SAFE upstream values
        assert!(d.require_nolog);
        assert!(d.cache);
        assert_eq!(d.blocked_query_response.as_deref(), Some("hinfo"));
    }

    /// (d) a malformed / wrong-typed TOML fail-softs to the safe upstream `Default` with NO panic, while
    /// the typed `from_toml` NAMES the failure (so the UI can surface it) instead of swallowing it.
    #[test]
    fn malformed_toml_fail_softs_to_default_no_panic() {
        let malformed = [
            "this is not valid toml at all === [[",
            "cache = \"yes\"\n", // bool field given a string ⇒ type error
            "timeout = 'not-a-number'\n", // i32 field given a string ⇒ type error
            "max_clients = [1, 2, 3]\n", // i32 field given an array ⇒ type error
            "listen_addresses = ['127.0.0.1:53'\n", // unterminated array
            "[sources.x\nbroken header", // unterminated table header
            "netprobe_timeout = 99999999999999999999", // i32 overflow
        ];

        for bad in malformed.iter().copied() {
            // (d-1) fail-soft: degrade to the safe upstream Default, never a panic / a bricked resolver.
            let cfg = from_toml_or_default(bad);
            assert_eq!(cfg.listen_addresses, vec!["127.0.0.1:5354".to_string()]);
            assert!(cfg.require_nolog);
            assert!(cfg.cache);
            assert_eq!(cfg.blocked_query_response.as_deref(), Some("hinfo"));

            // (d-2) the typed path NAMES the failure instead of swallowing it.
            match from_toml(bad) {
                Err(ConfigError::TomlParse { reason }) => assert!(!reason.is_empty()),
                other => panic!("expected a typed TomlParse error for {bad:?}, got {other:?}"),
            }
        }
    }
}

// ===========================================================================================
// THE SHIPPED-ASSET BINDING (checkpoint 100)
// ===========================================================================================
//
// Every round-trip test above proves the model against `REAL_EXAMPLE_TOML` — an INLINE r#"..."#
// copy at the top of the test module. That is a hand-written sample, so all of them stay green
// while the file that ACTUALLY SHIPS drifts away from the model. The asset users boot from is
// `libumdnscrypt/src/main/assets/dnscrypt.zip` -> `app_data/dnscrypt-proxy/dnscrypt-proxy.toml`,
// and nothing in this crate had ever parsed it.
//
// `shipped/dnscrypt-proxy.toml` is that file, byte-for-byte, and `tools/shipped/check-shipped-toml.js`
// fails if the two ever diverge. So this test executes the REAL implementation against the REAL
// shipped bytes instead of a copy of them.
//
// CORRECTION 2026-08-01, because the sentence above was FALSE for as long as it existed. It named
// `tools/check-shipped-toml.sh`, and NO SUCH FILE was ever in the tree -- so nothing enforced the
// binding, and the two copies had already drifted apart by three lines: the project-wide
// `tordnscrypt` -> `libumdnscrypt` rename landed on this text copy and missed the one inside
// `dnscrypt.zip`, because grep cannot see into a binary archive.
//
// The consequence is the exact overclaim this repo hunts. The test below was GREEN the whole time
// while testing a file that no device ever receives -- a comment asserting a guarantee that no
// instrument provided. The zip has been resynced and the checker now exists, reads the zip
// directly (no unzip binary, no temp dir), has a size floor so it cannot pass on a truncated
// entry, and runs in CI. Its negative control is the stale zip, which it rejects with the three
// differing lines printed.
//
// Tortä's DNSCrypt is entirely Rust: only the .toml / .log / config files are read and rewritten,
// through this serde model. That is why the shipped config is ~4 KB while upstream's Go
// `example-dnscrypt-proxy.toml` is ~39 KB — ours is the subset this struct actually round-trips,
// NOT a trimmed-down copy of upstream. Pulling upstream's config in wholesale would be a
// regression: with no `deny_unknown_fields`, the extra keys import silently and are then DROPPED
// on the first rewrite, so the file would quietly lose most of itself the first time it is saved.
#[cfg(test)]
mod shipped_asset {
    use super::*;

    /// The exact bytes shipped inside `assets/dnscrypt.zip`.
    const SHIPPED_TOML: &str = include_str!("shipped/dnscrypt-proxy.toml");

    /// The shipped config must import, export and re-import LOSSLESS through the live model —
    /// the same contract the inline example gets, but on the bytes that reach a real device.
    #[test]
    fn the_shipped_config_round_trips_through_the_live_model() {
        let cfg = from_toml(SHIPPED_TOML).expect("the SHIPPED dnscrypt-proxy.toml must import");
        let exported = to_toml(&cfg).expect("export must be B2-safe (values before tables)");
        let back = from_toml(&exported).expect("the exported view must re-import");
        // The SAME comparator the inline-example tests use — a weaker hand-rolled check here would
        // let the shipped file pass a test the sample file could not.
        super::real_example_tests::assert_round_trip_eq(&cfg, &back);
    }

    /// The shipped config must be USABLE, not merely parseable. A file that imports to all
    /// defaults would satisfy the round-trip above and still boot a device to nothing, so the
    /// values that make it Tortä's config are pinned here.
    #[test]
    fn the_shipped_config_is_not_an_empty_default() {
        let cfg = from_toml(SHIPPED_TOML).expect("imports");
        assert!(
            cfg.listen_addresses.iter().any(|a| a.contains("5354")),
            "Tortä listens on 5354, not the upstream :53 default: {:?}",
            cfg.listen_addresses
        );
        assert!(!cfg.server_names.is_empty(), "shipped config must name servers");
        assert!(cfg.ipv4_servers, "IPv4 servers must be enabled");
    }
}
