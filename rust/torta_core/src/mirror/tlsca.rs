/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ★ #66 — the DEVICE CA: how Centauri answers a browser as the CDN, so an asset can be served LOCALLY.
//!
//! ## Why a certificate is the missing piece
//! Centauri's thesis is *absorb once, serve forever*: a watched CDN asset is fetched at most ONE time
//! and is served from the on-device content-addressed store — privately, offline, sub-millisecond —
//! every time after. That already works on the `:80` hairpin ([`super::server`] → [`super::serve`]).
//!
//! On `:443` it could not work at all, for one reason: a browser opens TLS and expects a certificate for
//! `ajax.googleapis.com`. We do not have Google's key and never will. Without a certificate the flow
//! cannot even be decrypted, so the serve path — which is otherwise complete — is unreachable, and the
//! asset has to come from the CDN over the network every single time.
//!
//! This module closes exactly that gap: a CA that lives and dies on ONE device, mints a leaf per
//! hostname on demand, and lets the local mirror answer the handshake. What is behind the handshake is
//! not a proxy — it is the signed catalog and the local store.
//!
//! ## The trust posture (say the uncomfortable part out loud)
//! A device CA that a browser trusts can, by construction, impersonate any site to that browser. That is
//! a real and serious power, so it is fenced in hard:
//!
//! - **The private key never leaves the device and is never transmitted.** It is generated on-device at
//!   first arm (the [`super::devkey`] First-Boot precedent) and only the PUBLIC certificate is ever
//!   exported, for the user to install deliberately.
//! - **A leaf is only ever minted for a host the signed catalog already watches**
//!   ([`super::localcdn::is_cdn_host`]). Asking this CA for `yourbank.example` returns nothing. The CA's
//!   reach is bounded by the same minisign-signed catalog that bounds everything else in Centauri.
//! - **Trust is opt-in and revocable**: nothing is installed silently, and deleting the CA from the OS
//!   trust store instantly returns every flow to ordinary end-to-end TLS.
//! - **The user is never asked to trade privacy for function.** The point of the CA is that the asset is
//!   served from their own device instead of fetched from a CDN that would learn their address.
//!
//! ## What it is NOT
//! This is not a general TLS-intercepting proxy and must never become one. The ONLY thing served behind
//! a minted leaf is a catalog-authorized, hash-verified asset out of the local store. An unauthorized
//! path fail-closes exactly as it does on the `:80` leg — it does not fall through to the network.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

/// How long a minted leaf claims to be valid. Deliberately SHORT: these certificates are minted on
/// demand and cached in RAM, so a long life buys nothing, while a short one bounds the damage if a leaf
/// ever escaped the process.
const LEAF_VALIDITY_DAYS: i64 = 30;

/// How long the device CA itself is valid. Long enough that a user is not re-installing it constantly,
/// short enough to expire on its own if Centauri is abandoned.
const CA_VALIDITY_DAYS: i64 = 825;

/// The most distinct hostnames we will hold minted leaves for. The watched-CDN catalog is ~43 hosts, so
/// this is generous; the cap exists so a pathological client cannot grow the map without bound.
const MAX_CACHED_LEAVES: usize = 256;

/// How many days BEFORE a leaf actually expires it gets re-minted. The margin exists so a handshake
/// that begins moments before the boundary still receives a certificate that is valid for its whole
/// life, rather than one that expires mid-session.
const LEAF_RENEW_MARGIN_DAYS: i64 = 2;

/// A minted leaf plus the moment it must be replaced. Caching the certificate WITHOUT this was an
/// outage waiting to happen — see [`CentauriResolver::leaf_for`].
struct CachedLeaf {
    key: Arc<CertifiedKey>,
    renew_after: time::OffsetDateTime,
}

/// The on-device certificate authority. Minted once, held for the process lifetime, and used ONLY to
/// sign leaves for hosts the signed catalog watches.
pub(crate) struct DeviceCa {
    /// The CA certificate in DER — the ONLY part that is ever exported.
    cert_der: CertificateDer<'static>,
    /// The CA certificate in PEM — what the user installs into the OS trust store.
    cert_pem: String,
    /// The CA signing key. NEVER exported, never logged, never leaves this struct.
    key_pair: rcgen::KeyPair,
    /// The parsed CA, kept so each leaf can be signed without re-parsing.
    ca: rcgen::Certificate,
}

impl DeviceCa {
    /// Mint a fresh device CA. Called once per install (the caller persists the result).
    pub(crate) fn mint() -> Result<Self, String> {
        let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("ca keypair: {e}"))?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .map_err(|e| format!("ca params: {e}"))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        // A constrained CA (path length 0) can sign leaves but never another CA — it cannot be used to
        // build a chain beyond exactly what Centauri mints.
        params.distinguished_name = distinguished_name("Yeah Tortae Centauri Device CA");
        // Month-granular anchor — the CA lands in the trust store, where any app can read these dates.
        let anchor = ca_not_before();
        params.not_before = anchor;
        params.not_after = plus_days(anchor, CA_VALIDITY_DAYS);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca = params
            .self_signed(&key_pair)
            .map_err(|e| format!("ca self-sign: {e}"))?;
        Ok(DeviceCa {
            cert_der: ca.der().clone(),
            cert_pem: ca.pem(),
            key_pair,
            ca,
        })
    }

    /// Rebuild a CA from a previously persisted PEM pair, so the user's trust decision survives a
    /// restart. A malformed pair is an error, never a silent re-mint: silently minting a NEW CA would
    /// leave the user trusting a key that no longer signs anything, which looks exactly like a broken
    /// install with no explanation.
    pub(crate) fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        let key_pair = rcgen::KeyPair::from_pem(key_pem).map_err(|e| format!("ca key pem: {e}"))?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| format!("ca cert pem: {e}"))?;
        let ca = params
            .self_signed(&key_pair)
            .map_err(|e| format!("ca rebuild: {e}"))?;
        Ok(DeviceCa {
            cert_der: ca.der().clone(),
            cert_pem: cert_pem.to_string(),
            key_pair,
            ca,
        })
    }

    /// The CA certificate as PEM — what the user installs. PUBLIC material only.
    pub(crate) fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA PRIVATE key as PEM, for persistence to app-private storage ONLY.
    ///
    /// This is the one accessor that hands out secret material. It exists solely so the CA survives a
    /// restart (without it the user would have to re-trust a new CA on every launch, training exactly
    /// the reflex — "just accept the certificate" — that this whole design should discourage). The
    /// caller MUST write it to app-private storage and nowhere else; it is never logged, never shown in
    /// the UI, and never leaves the device.
    pub(crate) fn key_pem_for_private_storage(&self) -> String {
        self.key_pair.serialize_pem()
    }

    /// Mint a leaf for `host`, signed by this CA.
    ///
    /// The caller is responsible for having checked that `host` is catalog-watched — [`CentauriResolver`]
    /// enforces that on every path that reaches here.
    fn mint_leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let leaf_key = rcgen::KeyPair::generate().map_err(|e| format!("leaf keypair: {e}"))?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
            .map_err(|e| format!("leaf params: {e}"))?;
        params.distinguished_name = distinguished_name(host);
        // Day-granular anchor — a leaf is short-lived, so a month anchor would eat its validity, but it
        // still must not timestamp the exact instant the user visited this host.
        let anchor = leaf_not_before();
        params.not_before = anchor;
        params.not_after = plus_days(anchor, LEAF_VALIDITY_DAYS);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let leaf = params
            .signed_by(&leaf_key, &self.ca, &self.key_pair)
            .map_err(|e| format!("leaf sign: {e}"))?;

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            leaf_key.serialize_der(),
        ));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("leaf signing key: {e}"))?;
        // The chain is leaf-then-CA so a client that trusts the CA can build the path without having to
        // fetch anything (there is no AIA to fetch from — this CA is not on any network).
        let chain = vec![leaf.der().clone(), self.cert_der.clone()];
        Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
    }
}

/// The rustls certificate resolver: mints (and caches) one leaf per SNI hostname, on demand.
///
/// Using rustls' own [`ResolvesServerCert`] hook rather than pre-building a config per host means ONE
/// `ServerConfig` serves every watched CDN, and the hostname used for the certificate is the one rustls
/// itself parsed out of the ClientHello — not a value we re-derived, so the certificate can never
/// disagree with the handshake it is answering.
pub(crate) struct CentauriResolver {
    ca: DeviceCa,
    /// Minted leaves, keyed by lowercase hostname. A `Mutex` (not `RwLock`): minting is rare, lookups
    /// are cheap, and the map is tiny — an uncontended `Mutex` is the simpler correct thing.
    leaves: Mutex<HashMap<String, CachedLeaf>>,
}

impl std::fmt::Debug for CentauriResolver {
    /// Hand-written so no derive can ever print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CentauriResolver")
            .field("leaves_cached", &self.leaves.lock().map(|m| m.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl CentauriResolver {
    pub(crate) fn new(ca: DeviceCa) -> Self {
        CentauriResolver {
            ca,
            leaves: Mutex::new(HashMap::new()),
        }
    }

    /// Resolve (minting on first use) the leaf for `host`, or `None` if the catalog does not watch it.
    ///
    /// THE FENCE. Every certificate this CA ever signs passes through this check, so the CA's reach is
    /// exactly the signed catalog's reach and nothing more.
    fn leaf_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let host = host.to_ascii_lowercase();
        if !super::localcdn::is_cdn_host(&host) {
            return None;
        }
        let mut cache = self.leaves.lock().ok()?;

        // ★ AUTO-RENEWAL — a cached leaf is reused only while it is still VALID.
        //
        // Leaves live [`LEAF_VALIDITY_DAYS`] (30). The mirror lives as long as the tunnel does, which on
        // a phone is months: a leaf minted on day 1 and cached forever would expire on day 31 and every
        // HTTPS serve for that host would fail from then on, silently, until the user rebooted. Nothing
        // in the app would say why. So the cache stores WHEN to renew and re-mints past that point.
        //
        // This costs one timestamp comparison per handshake on the hot path. The expensive part —
        // keygen plus a signature — runs once per host per renewal window, never per request, so
        // Centauri's serving latency is untouched.
        let now = time::OffsetDateTime::now_utc();
        if let Some(found) = cache.get(&host) {
            if now < found.renew_after {
                return Some(Arc::clone(&found.key));
            }
            // Past the renewal point: fall through and mint a replacement over it.
        } else if cache.len() >= MAX_CACHED_LEAVES {
            return None; // bounded: refuse a NEW host rather than grow without limit
        }

        let minted = self.ca.mint_leaf(&host).ok()?;
        // Renew with margin so a leaf is replaced BEFORE it expires, never after: a client that starts a
        // handshake moments before the boundary must still get a certificate valid for that handshake.
        let renew_after = plus_days(leaf_not_before(), LEAF_VALIDITY_DAYS - LEAF_RENEW_MARGIN_DAYS);
        cache.insert(
            host,
            CachedLeaf {
                key: Arc::clone(&minted),
                renew_after,
            },
        );
        Some(minted)
    }
}

impl ResolvesServerCert for CentauriResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // No SNI ⇒ no certificate. We refuse rather than guess: presenting a certificate for a name the
        // client did not ask for is precisely the behavior a trusted CA must never exhibit.
        self.leaf_for(hello.server_name()?)
    }
}

/// Build the `ServerConfig` the mirror's TLS acceptor uses. No client authentication (a browser on the
/// same device is the client), ALPN advertising HTTP/1.1 only — the mirror's serve path is HTTP/1.1, and
/// advertising h2 we do not speak would break every flow that accepted it.
pub(crate) fn server_config(resolver: Arc<CentauriResolver>) -> Arc<rustls::ServerConfig> {
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// A distinguished name carrying `cn`. Kept minimal on purpose — a certificate that never leaves one
/// device has no use for organizational fields, and every extra field is another thing to get wrong.
fn distinguished_name(cn: &str) -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, cn);
    dn
}

/// ★ PRIVACY — certificate validity is COARSENED so it cannot timestamp the user.
///
/// A second-precision `notBefore` is not a neutral detail once the CA is installed in the device trust
/// store: any app on the phone may enumerate trusted CAs, so an exact mint time publishes the moment
/// this user first armed Centauri — a stable, high-resolution behavioural fact attached to a
/// certificate that is already device-unique by construction. Two devices that armed a minute apart
/// would be trivially distinguishable, and an exported certificate (a backup, a support log) would
/// carry that moment with it forever.
///
/// A device CA cannot avoid being unique — its key IS the uniqueness, and that is the point of it. What
/// it CAN avoid is disclosing anything ABOUT the device or its owner. So every human-readable field is
/// held constant across the whole install base: the subject is a fixed string with no device name, and
/// the validity window is snapped to a coarse calendar anchor shared by everyone who armed in the same
/// period. What remains is a random serial and a public key, which carry no meaning on their own.
///
/// The CA anchors to the START OF THE UTC MONTH (12 distinct values a year), the leaves to the start of
/// the UTC day — leaves are short-lived, so a month anchor would consume their validity. Both then step
/// back one further day, which both guarantees the ≥1 day of clock-skew tolerance Android genuinely
/// needs and keeps the anchor from landing exactly on a boundary.
fn ca_not_before() -> time::OffsetDateTime {
    let today = time::OffsetDateTime::now_utc().date();
    let month_start = time::Date::from_calendar_date(today.year(), today.month(), 1).unwrap_or(today);
    month_start.midnight().assume_utc() - time::Duration::days(1)
}

/// Day-granular counterpart for leaf certificates (see [`ca_not_before`] for the reasoning).
fn leaf_not_before() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc().date().midnight().assume_utc() - time::Duration::days(1)
}

/// `anchor + days` — derived from an already-coarsened anchor, so the expiry is equally coarse and
/// leaks nothing the anchor did not.
fn plus_days(anchor: time::OffsetDateTime, days: i64) -> time::OffsetDateTime {
    anchor + time::Duration::days(days)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ PRIVACY LAW — no certificate this device mints may disclose WHEN it was minted.
    ///
    /// The CA is installed into the device trust store, where any app can read its validity dates. A
    /// second-precision `notBefore` would publish the moment the user first armed Centauri and would
    /// distinguish two devices that armed minutes apart. This pins the coarsening: the CA anchor is the
    /// first instant of a UTC month (less a day), the leaf anchor the first instant of a UTC day (less a
    /// day) — both carry ZERO sub-day entropy, and both stay at least a day in the past so Android
    /// clock skew still accepts a fresh certificate.
    #[test]
    fn certificate_validity_carries_no_sub_day_timestamp() {
        for anchor in [ca_not_before(), leaf_not_before()] {
            assert_eq!(anchor.hour(), 0, "hour must be zeroed: {anchor}");
            assert_eq!(anchor.minute(), 0, "minute must be zeroed: {anchor}");
            assert_eq!(anchor.second(), 0, "second must be zeroed: {anchor}");
            assert_eq!(anchor.nanosecond(), 0, "nanosecond must be zeroed: {anchor}");
            assert!(
                anchor < time::OffsetDateTime::now_utc(),
                "anchor must be backdated for clock-skew tolerance: {anchor}"
            );
        }
        // The CA anchor is the coarser of the two: it sits exactly one day before a month boundary, so
        // stepping a day forward always lands on the 1st. That is what makes it shared by everyone who
        // armed in the same month.
        let ca = ca_not_before();
        assert_eq!(
            (ca + time::Duration::days(1)).day(),
            1,
            "CA anchor must be one day before a month start: {ca}"
        );
        let expiry = plus_days(ca, CA_VALIDITY_DAYS);
        assert_eq!(expiry.second(), 0, "expiry inherits the coarse anchor");
    }

    /// A CA mints, and its PEM is a real certificate the user could install.
    #[test]
    fn device_ca_mints_and_exports_public_pem() {
        let ca = DeviceCa::mint().expect("CA must mint");
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(
            !ca.cert_pem().contains("PRIVATE KEY"),
            "the exported PEM must be PUBLIC material only — never the signing key"
        );
    }

    /// A CA survives a persist/reload round-trip, so the user's trust decision is not thrown away on
    /// every restart (which would train them to blind-accept certificates).
    #[test]
    fn device_ca_round_trips_through_pem() {
        let ca = DeviceCa::mint().expect("mint");
        let cert_pem = ca.cert_pem().to_string();
        let key_pem = ca.key_pem_for_private_storage();
        let reloaded = DeviceCa::from_pem(&cert_pem, &key_pem).expect("reload");
        assert_eq!(
            reloaded.cert_pem(),
            cert_pem,
            "a reloaded CA must be the SAME authority the user already trusted"
        );
    }

    /// THE FENCE, proven: the CA mints for a catalog-watched CDN host and REFUSES everything else.
    ///
    /// This is the assertion that keeps a device CA from being a general interception tool. If it ever
    /// fails, the CA can impersonate arbitrary sites to the user's browser.
    #[test]
    fn mints_only_for_catalog_watched_hosts() {
        let resolver = CentauriResolver::new(DeviceCa::mint().expect("mint"));
        assert!(
            resolver.leaf_for("ajax.googleapis.com").is_some(),
            "a watched CDN host must get a leaf — this is the whole serve leg"
        );
        for forbidden in [
            "yourbank.example",
            "accounts.google.com",
            "localhost",
            "evil.test",
        ] {
            assert!(
                resolver.leaf_for(forbidden).is_none(),
                "{forbidden} is NOT catalog-watched — the device CA must refuse to sign for it"
            );
        }
    }

    /// A second request for the same host reuses the cached leaf rather than minting again (minting is
    /// the expensive part of a handshake we want to keep sub-millisecond).
    #[test]
    fn leaves_are_cached_per_host() {
        let resolver = CentauriResolver::new(DeviceCa::mint().expect("mint"));
        let first = resolver.leaf_for("ajax.googleapis.com").expect("first");
        let second = resolver.leaf_for("ajax.googleapis.com").expect("second");
        assert!(
            Arc::ptr_eq(&first, &second),
            "the same host must reuse ONE minted leaf"
        );
    }

    /// Case is normalized — SNI arrives in whatever case the client chose.
    #[test]
    fn host_matching_is_case_insensitive() {
        let resolver = CentauriResolver::new(DeviceCa::mint().expect("mint"));
        assert!(resolver.leaf_for("AJAX.GoogleAPIs.CoM").is_some());
    }
}
