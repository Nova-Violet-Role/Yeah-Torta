/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! DNSCrypt v2 — **the namesake transport** of this DNSCrypt-only app. Wave 2d.
//!
//! Unlike the QUIC transports (DoH3/DoQ, `#[cfg(feature = ...)]`), DNSCrypt is a **BASE transport**:
//! always compiled, the reason the app exists. It is the one transport that does NOT ride rustls/TLS
//! at all — its security comes from a hand-rolled v2 datapath:
//!
//!   1. **stamp** — parse the `sdns://` DNS Stamp (protocol `0x01`) → resolver `SocketAddr`, provider
//!      name (`2.dnscrypt-cert.<provider>`), and the provider's **Ed25519** public key. (This file
//!      carries a small self-contained stamp decoder because the `dnsstamps` crate is ENCODE-ONLY —
//!      see the dep note in `Cargo.toml`.) The `0x81` anonymized-relay stamp is parsed + STORED, and
//!      (Slice 2 / T23) the relay hop is **WIRED**: when a relay chain is attached via
//!      [`DnsCrypt::set_relays`], the encrypted query AND the cert-fetch TXT are wrapped in the
//!      anonymized-DNSCrypt envelope (8×0xff + 0x00 0x00 + resolver `ip.To16()` + port BE + payload,
//!      [`wrap_for_relay`]) and sent to the first relay; the resolver's reply comes back verbatim.
//!   2. **cert** (T14) — fetch the provider cert via a **plaintext** DNS TXT query (the cert is
//!      Ed25519-SIGNED, so a plaintext fetch is correct and is NOT a T13 violation — only the actual
//!      user queries must be encrypted), then **Ed25519-verify it against the stamp's provider pk**,
//!      enforce `ts_start..ts_end`, and pick the **HIGHEST** valid `es_version` (XChaCha20-Poly1305 =
//!      v2, XSalsa20-Poly1305 = v1) — **never downgrade**. The verified cert yields the short-term
//!      resolver pk + the client-magic.
//!   3. **encrypt** (T13/T15/T21) — X25519(client ephemeral secret, resolver short-term pk) → the NaCl
//!      `crypto_box` shared key (HSalsa20/HChaCha20 of the X25519 point, per es-version); frame
//!      `<client-magic><client-pk><client-nonce><AEAD(padded query)>`. The AEAD is the NaCl
//!      `crypto_secretbox` construction (Poly1305 over the ciphertext only, tag-prepended) via the
//!      `crypto_secretbox` crate — XChaCha20Poly1305 for es-v2, XSalsa20Poly1305 for es-v1. The
//!      **client nonce is CSPRNG and NEVER reused** (T15); the query is **RFC-8467 padded** to a
//!      64-byte multiple before sealing (T21). Encrypted-only — there is no plaintext query path, ever
//!      (T13).
//!   4. **send / receive** — UDP to the resolver. The TC (truncation) bit drives a TCP fallback (2-byte
//!      length-prefixed, RFC 7766) ONLY on the plaintext cert-fetch path; an encrypted reply is taken
//!      from UDP as-is (FIX 2 — its byte[2] is the resolver magic, not a DNS header bit). On the reply
//!      verify the **resolver magic** (`r6fnvWj8`) + the **client-nonce echo**, AEAD-open (a tampered
//!      byte fails the tag → **drop, no crash**), then **strip the padding**. The decrypted answer is a
//!      normal DNS message → **opaque bytes out**; the resolver runs `dns::validate_response` on it,
//!      UNCHANGED (this transport never parses DNS).
//!
//! No qname in logs (T20); the response read is bounded at 64 KiB (T6).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// FIX 1 — the DNSCrypt v2 datapath seals/opens through RustCrypto's `crypto_secretbox`, the NaCl
// `crypto_secretbox` construction (pure-Rust, NO aws-lc / ring). For BOTH es-versions it computes
// Poly1305 over the CIPHERTEXT ONLY — no RFC-8439 length block, no AAD — with the Poly1305 key taken
// from the first 32 bytes of the stream-cipher keystream (block 0) and encryption from block 1, and it
// PREPENDS the tag (tag||ciphertext). That is byte-for-byte libsodium `crypto_secretbox_*`, exactly
// what a real DNSCrypt resolver expects:
//   * es-v2 → `crypto_secretbox::XChaCha20Poly1305` (the libsodium XChaCha20 variant), and
//   * es-v1 → `crypto_secretbox::XSalsa20Poly1305` (classic NaCl secretbox).
// This replaces the previous es-v2 path through `chacha20poly1305 0.10.1`, whose Poly1305 MAC also
// hashes a 16-byte length block (its `cipher.rs::authenticate_lengths`) — the IETF AEAD_XChaCha20
// construction, which produces a DIFFERENT, WRONG tag VALUE for NaCl crypto_box (the headline bug).
//
// `aead`'s `Aead`/`KeyInit` traits come in via `crypto_secretbox`'s own re-export; the prepend-tag
// `Aead::encrypt`/`decrypt` (overridden by `crypto_secretbox` to put the tag at the front) is all we
// need, so no detached/`GenericArray` plumbing here anymore.
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{
    XChaCha20Poly1305 as NaclXChaCha20Poly1305, XSalsa20Poly1305 as NaclXSalsa20Poly1305,
};
use ed25519_dalek::{Signature, VerifyingKey};
use x25519_dalek::{PublicKey, StaticSecret};

// ★ PQDNSCrypt (es-version 0x0003, the v2.1.17 "DNSCrypt 2026" absorb) — X-Wing hybrid post-quantum
// KEM (X25519 × ML-KEM-768). The client side needs ONLY the encapsulation key: parse the resolver's
// 1216-byte X-Wing pk out of the SIGNED 1320-byte cert, encapsulate against it with 64 fresh CSPRNG
// bytes per query (`encapsulate_deterministic` is exactly `encapsulate_with_rng` minus the rand-core
// version bridge — the crate draws 64 bytes and calls it, x-wing-0.1.0/src/lib.rs:134-146), then bind
// the KEM shared secret to the signed cert via HKDF-SHA256. The AEAD stays the NaCl XChaCha20 secretbox
// ABOVE (upstream seals PQ queries with the same `xsecretbox`, crypto.go:233) — no new cipher.
use hkdf::Hkdf;
use sha2::Sha256;
use x_wing::EncapsulationKey as XWingEncapsulationKey;

use super::transport::{ExchangeFuture, Transport, TransportError, WarmFuture};

/// DNS Stamp protocol id for a DNSCrypt (v2) resolver stamp. A stamp whose first byte is anything
/// else (e.g. `0x02` = DoH, `0x81` = anonymized-DNSCrypt relay) is NOT a DNSCrypt resolver stamp and
/// is rejected by [`DnsCrypt::new`].
const STAMP_PROTO_DNSCRYPT: u8 = 0x01;

/// DNS Stamp protocol id for an anonymized-DNSCrypt **relay** stamp (T23, WIRED Slice 2). Parsed by
/// [`parse_relay_stamp`] into a [`RelayStamp`]; the relay hop is implemented in [`wrap_for_relay`] /
/// [`relayed_udp_then_tcp`] and dialed when a relay chain is attached to [`DnsCrypt`]. `#[allow]`:
/// the parser + this constant are exercised by the Slice 2 tests + the `pub` `parse_relay_chain` API,
/// but not yet by an internal caller (the pool wiring is a sibling slice); silence the dead-code lint
/// the same way the original scaffold did.
const STAMP_PROTO_RELAY: u8 = 0x81;

/// `sdns://` scheme prefix carried by every DNS Stamp.
const SDNS_PREFIX: &str = "sdns://";

/// Length of a provider Ed25519 public key (T14 verifies the cert against this).
const PROVIDER_PK_LEN: usize = 32;

/// The 8-byte magic that prefixes a DNSCrypt **certificate** TXT record (`DNSC` + version words).
const CERT_MAGIC: [u8; 4] = *b"DNSC";

/// The 8-byte magic that prefixes every DNSCrypt **resolver response** (`r6fnvWj8`). The decrypt path
/// verifies the reply starts with this before trusting any of it.
const RESOLVER_MAGIC: [u8; 8] = *b"r6fnvWj8";

/// es-version 2 — XChaCha20-Poly1305 (24-byte nonce, modern default). Preferred over v1.
const ES_XCHACHA: u16 = 0x0002;
/// es-version 1 — XSalsa20-Poly1305 (NaCl crypto_box, 24-byte nonce). The legacy fallback.
const ES_XSALSA: u16 = 0x0001;
/// ★ es-version 3 — X-Wing post-quantum hybrid KEM ("PQDNSCrypt" / "DNSCrypt 2026", upstream v2.1.17,
/// dnscrypt_certs.go:117-118). The KEM replaces the X25519 exchange; the AEAD stays the NaCl XChaCha20
/// secretbox. Preferred over v2 (never downgrade — the es-major selection order already does this).
const ES_XWING_PQ: u16 = 0x0003;

// ---------------------------------------------------------------------------------------------------
// ★ #97 — THE PQ WITNESS. The X-Wing engine has run on every eligible query since #2 sealed it, and
// NOTHING outside this file could see it: no getter, no export, no feed, no tile (measured — an
// exhaustive `pqdnscrypt|x-wing|post-quantum|0x0003` sweep of rust/torta_ui returned ZERO hits). A
// security property the user cannot verify is a claim, not a proof. These two counters are the proof:
// they are bumped at the ONE dispatch fork in `encrypted_exchange`, so every encrypted DNSCrypt
// exchange lands in exactly one of them and the pair can never double-count or disagree.
//
// Counters, NOT a boolean "PQ is on": the honest answer to "is my DNS post-quantum protected?" is how
// many exchanges actually rode the X-Wing KEM versus the classic X25519 path — a resolver that
// publishes no es-0x0003 cert leaves `PQ_EXCHANGES` at 0 while the gate is still ON, and that
// distinction is exactly what a user needs to see. A cold engine reads 0/0 and the panel renders the
// house's honest empty-state, never a fabricated "protected".
// ---------------------------------------------------------------------------------------------------

/// Encrypted exchanges that rode the X-Wing PQ KEM (es-0x0003). Bumped in `encrypted_exchange` on the
/// PQ branch ONLY — after the cert has been Ed25519-verified and selected, so it counts NEGOTIATED
/// post-quantum traffic, never an intention.
static PQ_EXCHANGES: AtomicU64 = AtomicU64::new(0);

/// Encrypted exchanges that rode the classic X25519 path (es-0x0001/0x0002). The denominator half of
/// the same fork — together with [`PQ_EXCHANGES`] this is the full census of encrypted exchanges.
static CLASSIC_EXCHANGES: AtomicU64 = AtomicU64::new(0);

/// ★ #97 — read the PQ witness as `(pq_exchanges, classic_exchanges)`. Relaxed loads: these are display
/// counters on a monotonic pair, never a synchronisation edge. A cold engine returns `(0, 0)` and the
/// caller is responsible for rendering that as the honest unknown rather than as "not protected".
pub(crate) fn pq_exchange_counts() -> (u64, u64) {
    (
        PQ_EXCHANGES.load(Ordering::Relaxed),
        CLASSIC_EXCHANGES.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------------------------------
// ★ PQDNSCrypt constants — every value mirrors upstream pq.go:19-48 EXACTLY (measured, not assumed).
// ---------------------------------------------------------------------------------------------------

/// X-Wing encapsulation-key size: ML-KEM-768 ek (1184) || X25519 pk (32). Cert bytes [72..1288].
const PQ_XWING_PK_LEN: usize = 1216;
/// X-Wing ciphertext size: ML-KEM-768 ct (1088) || X25519 ephemeral pk (32). Sent in every fresh query.
const PQ_XWING_CT_LEN: usize = 1120;
/// A PQ cert is at least 1320 bytes: 72 (header+sig) + 1216 (pk) + 8 (magic) + 4+4+4 (serial/ts) + 12
/// (the PQ profile extension). The classic cert is 124 bytes + optional extensions.
const PQ_CERT_LEN: usize = 1320;
/// The 12-byte PQ profile extension at cert bytes [1308..1320], INSIDE the Ed25519-signed region —
/// upstream `pqProfileExtension()` (pq.go:36-48): `"PQD"` + ext-version 0x01 + es 0x0003 + kdf-id 0x01
/// (HKDF-SHA256) + aead-id 0x01 (XChaCha20-Poly1305 secretbox) + pk-size 1216 BE + ct-size 1120 BE.
/// The es-version is REPEATED here inside the SIGNED bytes — that echo is the PQ anti-downgrade anchor
/// (FIX 2, PQ edition): a flipped unsigned header can never disagree with this without being rejected.
const PQ_PROFILE_EXT: [u8; 12] = [
    0x50, 0x51, 0x44, // "PQD"
    0x01, // extension version
    0x00, 0x03, // es-version echo (ES_XWING_PQ) — signed, so the header flip is detectable
    0x01, // KDF id: HKDF-SHA256
    0x01, // AEAD id: XChaCha20-Poly1305 secretbox
    0x04, 0xC0, // pk size 1216 BE
    0x04, 0x60, // ct size 1120 BE
];
/// PQ response control-block magic ("PQDR") + version — the first bytes of a non-empty control block
/// the resolver prepends to the decrypted response body (pq.go:29-33, :284-309). We PARSE and STRIP the
/// block (mandatory for a correct body) but deliberately IGNORE the resumption ticket it may carry —
/// see [`pq_strip_control`] for the privacy rationale (per-query unlinkability > resume bandwidth).
const PQ_CONTROL_MAGIC: [u8; 4] = *b"PQDR";
/// The HKDF domain-separation prefix of the cert-binding context (pq.go:63).
const PQ_CONTEXT_LABEL: &[u8] = b"DNSCrypt-PQ-v1";
/// Padding floor for a FRESH (ciphertext-carrying) PQ query (pq.go:251): the 1120-byte KEM ciphertext
/// already dominates the frame length, so the body floor is one block, not [`MIN_PADDED`].
const PQ_FRESH_PAD_FLOOR: usize = 64;

/// DNSCrypt client nonce is 24 bytes total: a 12-byte CSPRNG half the client fills, then 12 zero bytes
/// the resolver fills in its response. T15: the 12-byte CSPRNG half is fresh per query, NEVER reused.
const HALF_NONCE_LEN: usize = 12;
const FULL_NONCE_LEN: usize = 24;

/// RFC-8467 / DNSCrypt block padding granularity. The padded plaintext (query + `0x80` + zeros) is a
/// multiple of this; DNSCrypt mandates 64-byte block alignment for the encrypted query (T21).
const PAD_BLOCK: usize = 64;
/// Minimum padded plaintext length DNSCrypt requires before block rounding (256 bytes). Keeps short
/// queries from leaking their length below this floor.
const MIN_PADDED: usize = 256;

/// T6 — never read more than 64 KiB of response (a DNS message tops out near the EDNS0 buffer).
const MAX_RESPONSE: usize = 64 * 1024;

/// The parsed pieces of a DNSCrypt `sdns://` resolver stamp that the datapath needs.
struct Stamp {
    /// The resolver's `IP:port` (DNSCrypt default port 443). Where the encrypted queries are sent.
    addr: SocketAddr,
    /// The provider name, e.g. `2.dnscrypt-cert.example.com` — the QNAME of the cert TXT lookup.
    provider_name: String,
    /// The provider's long-term **Ed25519** public key. T14: the fetched cert MUST verify against it.
    provider_pk: [u8; PROVIDER_PK_LEN],
}

/// A parsed anonymized-DNSCrypt **relay** stamp (`0x81`). Slice 2 (T23, DONE): the relay's address
/// is now WIRED into the live datapath — [`DnsCrypt::encrypted_exchange`] wraps the encrypted query in
/// the anonymized-DNSCrypt relay envelope (see [`wrap_for_relay`]) and dials THIS address instead of
/// the resolver, with the resolver `IP:port` embedded in the envelope. `#[allow(dead_code)]`:
/// constructed by the `pub` `parse_relay_stamp` (exercised by tests + the `pub` `parse_relay_chain`),
/// but the pool wiring that calls it is a sibling slice.
struct RelayStamp {
    /// The relay's `IP:port`. The relayed datapath (Slice 2) dials THIS instead of the resolver, with
    /// the resolver address embedded in the relayed envelope (8×0xff + 0x00 0x00 + ip.To16() + port BE).
    addr: SocketAddr,
}

/// A configured DNSCrypt v2 upstream. Cheap to share via `Arc` (the resolver wraps it). Holds the
/// parsed stamp + a cert cache that the datapath fills/refreshes; construction only parses the stamp
/// (no network), so a transiently-down resolver never blocks building the pool — exactly like DoH.
pub struct DnsCrypt {
    /// Stats label, e.g. `"dnscrypt:cloudflare"`.
    id: String,
    /// Resolver address parsed from the stamp (the UDP/TCP dial target when NO relay is configured).
    addr: SocketAddr,
    /// Provider name parsed from the stamp (the cert TXT QNAME).
    provider_name: String,
    /// Provider Ed25519 pk parsed from the stamp. T14: the fetched cert is Ed25519-verified against
    /// this before any short-term resolver key it carries is trusted.
    provider_pk: [u8; PROVIDER_PK_LEN],
    /// Cert cache, holding the single best (highest valid es_version) verified cert. The datapath
    /// fetches + Ed25519-verifies the provider cert once, picks the highest valid `es_version` (T14,
    /// never downgrade), and caches the resolved material here, refreshing once it expires. `Mutex` so
    /// a refresh is atomic w.r.t. concurrent exchanges.
    cert_cache: Mutex<Option<CachedCert>>,
    /// Anonymized-DNSCrypt relay chain (Slice 2 / T23). When NON-empty, queries are NOT sent directly
    /// to `addr`; instead each relay wraps the packet in the anonymized envelope (8×0xff + 0x00 0x00 +
    /// next-hop `ip.To16()` + port BE + payload) and the FIRST relay is dialed. An empty `Vec` = direct
    /// (no relay), the production pre-Slice-2 path, byte-identical. The Go lib uses ONE relay per query;
    /// the chain supports the spec's multi-hop nesting (relay→relay→resolver).
    relays: Vec<SocketAddr>,
    /// ★ G5 — the friendly NAME of the FIRST relay hop (the `## <name>` from `relays.md`), carried
    /// from the host slate as the `name` half of a `name|stamp` relay field so the query.log `relay`
    /// column can name the 0x81 anonymization hop. `None` = direct, or a relay attached WITHOUT a name
    /// (the Android/pre-G5 bare-stamp path — the row renders "-"). Display-only: it never touches the
    /// wire (the `relays` addr chain drives routing), so a wrong/absent name can never misroute.
    relay_name: Option<String>,
    /// ★ PQDNSCrypt gate — mirrors upstream's `pqdnscrypt` config toggle (default ON, config.go /
    /// dnscrypt_certs.go:124-126). When `false`, `select_best_cert` skips es-0x0003 certs entirely and
    /// the resolver negotiates the best CLASSIC cert instead; when `true` a valid PQ cert wins the
    /// es-major selection. Wired from `DnscryptProxyConfig.pqdnscrypt` by the configure seam.
    pq_enabled: bool,
}

/// One verified, in-window DNSCrypt cert's resolved material — what an `exchange` needs after T14 has
/// passed.
#[derive(Clone)]
struct CachedCert {
    /// The negotiated encryption-system version (2 = XChaCha20-Poly1305, 1 = XSalsa20-Poly1305).
    es_version: u16,
    /// The resolver's **short-term X25519** public key from the verified cert — the X25519 peer.
    resolver_pk: [u8; 32],
    /// The 8-byte client-magic that prefixes every encrypted query for this cert. This is the SIGNED
    /// (Ed25519-covered) field that binds the cipher choice — NOT the unsigned `es_version` header.
    /// FIX 2: the cipher is routed by THIS, so flipping the unsigned `es_version` byte cannot downgrade.
    client_magic: [u8; 8],
    /// Cert serial (`serial`, signed). FIX 3: freshness tiebreak — among equal-es_version valid certs,
    /// the HIGHEST serial wins (defeats retired-key pinning by a hostile resolver). Carried on the
    /// cached cert for diagnostics + a future cross-fetch freshness pin; read by the selection logic
    /// and tests. `#[allow(dead_code)]` matches the file's `RelayStamp` convention for a stored-but-
    /// not-yet-routed field.
    serial: u32,
    /// Cert validity end (`ts_end`, unix seconds). Widened to `u64` (FIX 4 / Y2106): compared against
    /// a `u64` `now`, never narrowing `now` to `u32`. T14: refresh before this; never use past it.
    ts_end: u64,
    /// ★ PQDNSCrypt material — `Some` iff `es_version == ES_XWING_PQ` (the parse guarantees the
    /// pairing). Carries the resolver's X-Wing encapsulation key + the precomputed HKDF cert context.
    pq: Option<PqCertMaterial>,
}

/// ★ The PQ half of a verified es-0x0003 cert: what a PQ exchange needs beyond the classic fields.
#[derive(Clone)]
struct PqCertMaterial {
    /// The resolver's X-Wing encapsulation key (1216 bytes), cert bytes [72..1288] — SIGNED material.
    pk: Vec<u8>,
    /// The HKDF cert-binding context (upstream `pqCertContext`, pq.go:59-73): `"DNSCrypt-PQ-v1"` ||
    /// es-version || protocol-minor || resolver-pk || client-magic || serial || ts-start || ts-end ||
    /// extensions — every byte of the SIGNED cert the shared key must be bound to. Precomputed at parse
    /// so the per-query HKDF never re-slices the raw cert.
    cert_context: Vec<u8>,
}

impl DnsCrypt {
    /// Build a DNSCrypt transport from an `sdns://` stamp. `id` is the stats label. Parses the stamp
    /// and **rejects a non-DNSCrypt stamp** (wrong scheme, bad base64, or a protocol byte != `0x01`).
    /// No network here — the cert fetch + verify happens lazily on the first `exchange` (so a
    /// transiently-down resolver never blocks pool construction, mirroring `Http2Doh::new`).
    pub fn new(id: &str, stamp: &str) -> Result<Self, TransportError> {
        let parsed = parse_dnscrypt_stamp(stamp)?;
        Ok(DnsCrypt {
            id: id.to_string(),
            addr: parsed.addr,
            provider_name: parsed.provider_name,
            provider_pk: parsed.provider_pk,
            cert_cache: Mutex::new(None),
            relays: Vec::new(),
            relay_name: None,
            // ★ PQ default ON — upstream v2.1.17 ships `pqdnscrypt = true` (config.go); the configure
            // seam overrides from `DnscryptProxyConfig.pqdnscrypt`.
            pq_enabled: true,
        })
    }

    /// ★ Set the PQDNSCrypt gate (the `pqdnscrypt` config toggle). `false` = never negotiate a PQ
    /// cert; the classic es-v2 path is used even when the resolver publishes es-0x0003. Takes effect
    /// on the NEXT cert (re)fetch; an already-cached cert is not evicted (matches upstream, where the
    /// toggle gates cert SELECTION, dnscrypt_certs.go:124-126).
    pub fn set_pq_enabled(&mut self, enabled: bool) {
        self.pq_enabled = enabled;
    }

    /// Set the anonymized-DNSCrypt relay chain (Slice 2 / T23). Each entry is a parsed relay stamp
    /// address (`0x81`). When non-empty, the encrypted query (AND the cert-fetch TXT query) is wrapped
    /// in the anonymized envelope and sent to the FIRST relay; the chain nests for multi-hop. Empty
    /// resets to direct (no relay) — the production pre-Slice-2 path. Builder-style: returns `&mut Self`
    /// for pool-construction ergonomics.
    ///
    /// WIRED: this is now the SINGLE place a relay chain is installed on a transport —
    /// [`with_relays`](Self::with_relays) delegates here rather than assigning the field itself, so
    /// the constructor and the setter cannot drift if installing a chain ever needs to do more than
    /// one assignment (invalidating a cert cache, say).
    pub fn set_relays(&mut self, relays: Vec<SocketAddr>) -> &mut Self {
        self.relays = relays;
        self
    }

    /// ★ G5 — attach the display NAME of the first relay hop (see the `relay_name` field). Builder-style
    /// (`&mut Self`), called by the configure seam right after [`with_relays`] once it has split the
    /// host's `name|stamp` relay field. `None` leaves the row's relay column at "-" (a bare-stamp relay).
    pub fn set_relay_name(&mut self, name: Option<String>) -> &mut Self {
        self.relay_name = name;
        self
    }

    /// Build a DNSCrypt transport with a pre-parsed relay chain (Slice 2 convenience over `new` +
    /// [`set_relays`](Self::set_relays)). Parses the resolver stamp, then attaches the relay chain
    /// THROUGH the setter, so there is one and only one way a chain gets installed.
    pub fn with_relays(
        id: &str,
        stamp: &str,
        relays: Vec<SocketAddr>,
    ) -> Result<Self, TransportError> {
        let mut me = Self::new(id, stamp)?;
        me.set_relays(relays);
        Ok(me)
    }

    /// Parse a list of `sdns://` relay stamps into the relay-address chain, accepting ONLY genuine
    /// relay stamps (`0x81`). A malformed or non-relay stamp is skipped (lenient in the same way the
    /// Go resolver silently drops a bad relay from its `via` list). Empty input → empty chain
    /// (direct, no anonymization).
    ///
    /// STRICTER THAN THE CONFIGURE PATH, DELIBERATELY, and that is what it is for. `configure` reads
    /// relay entries through [`parse_stamp_addr`], which by documented design accepts a DNSCrypt
    /// resolver stamp (`0x01`) as well as a relay stamp — so a user who pastes a *resolver* stamp
    /// into the relay field gets a working-looking configuration whose queries are not anonymized at
    /// all. This function is the strict reading that can tell the two apart, and it is what
    /// `dnscrypt_relay_check` (lib.rs) reports to the settings UI.
    pub fn parse_relay_chain(relay_stamps: &[&str]) -> Vec<SocketAddr> {
        relay_stamps
            .iter()
            .filter_map(|s| parse_relay_stamp(s).map(|r| r.addr))
            .collect()
    }

    /// Return a still-valid cached cert, or fetch + verify a fresh one over UDP (a plaintext TXT
    /// lookup of the provider name) and cache it. T14: every cert in the fetched set is Ed25519-checked
    /// against `provider_pk` and its `ts_start..ts_end` window enforced; the HIGHEST valid es_version
    /// wins; nothing else is ever cached. No qname is logged (T20).
    async fn ensure_cert(&self) -> Result<CachedCert, TransportError> {
        let now = unix_now();
        // Fast path: a cached cert that has not expired.
        if let Some(c) = self
            .cert_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            if c.ts_end > now {
                return Ok(c);
            }
        }

        // Plaintext TXT query for the provider name. CORRECT per protocol: the cert is Ed25519-signed,
        // so its authenticity does not depend on the channel — only the user's queries are encrypted.
        let query = build_txt_query(&self.provider_name);
        // PLAINTEXT cert fetch: a real DNS message, so the TC truncation bit is honoured (TCP fallback).
        // Slice 2: when a relay chain is configured, the cert fetch ALSO goes via the relay (matches the
        // upstream Go `FetchCurrentCert` + `prepareForRelay` path — the relay wraps the plaintext TXT
        // query in the anonymized envelope just like it wraps an encrypted query).
        //
        // ★ 2.1.18-absorb (PQ cert-fetch fragmentation hardening) — TCP-FIRST when PQ is enabled.
        // [`build_txt_query`] sends no EDNS0 OPT (deliberate: the classic 512-byte UDP ceiling), and a
        // PQ es-0x0003 cert is 1320 bytes — it can NEVER fit that ceiling. So with PQ on, the UDP leg
        // is either a guaranteed TC round-trip (compliant server → wasted RTT) or an over-limit reply
        // whose fragments are silently dropped on fragment-hostile paths — the fetch then just hangs
        // until the pool deadline (the exact reliability bug upstream 2.1.18 fixed, "including when
        // certificates are fetched through Anonymized DNSCrypt relays"). Dialing TCP first is strictly
        // better than upstream's fallback shuffle: deterministic, immune to fragmentation, and saves
        // the doomed UDP round-trip. Classic (pq_enabled=false) keeps the UDP-first + TC ladder — a
        // ~124-byte es-v2 cert fits UDP fine and UDP stays the cheapest lane.
        let response = if self.pq_enabled {
            relayed_tcp_then_udp(&self.relays, &self.addr, &query).await?
        } else {
            relayed_udp_then_tcp(&self.relays, &self.addr, &query, ReplyKind::PlaintextDns).await?
        };

        let certs = parse_cert_txts(&response)
            .ok_or_else(|| TransportError::BadResponse("cert response unparseable".into()))?;

        let best = select_best_cert(&certs, &self.provider_pk, now, self.pq_enabled).ok_or_else(
            || TransportError::BadResponse("no valid Ed25519-signed cert in window".into()),
        )?;

        // FIX 3, extended ACROSS refreshes. `select_best_cert` already picks the highest serial
        // WITHIN one fetch, but this replace path is reached after the cached cert expired, so a
        // resolver could hand back a RETIRED, lower-serial key and it would be installed silently.
        //
        // DETECTION, NOT ENFORCEMENT -- stated plainly because the distinction matters. Rejecting a
        // serial regression outright would be the stronger control, and I did not implement it: I
        // cannot establish from here that EVERY legitimate resolver's serial is monotone across a
        // key rotation, and a resolver that legitimately resets its serial would be bricked by a
        // hard refusal. Counting the regression surfaces a hostile resolver without inventing a
        // policy I cannot validate. If the field data ever shows regressions occur only under
        // attack, this becomes a rejection.
        {
            let mut guard = self.cert_cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old) = guard.as_ref() {
                if best.serial < old.serial {
                    CERT_SERIAL_REGRESSIONS.fetch_add(1, Ordering::Relaxed);
                }
            }
            *guard = Some(best.clone());
        }
        Ok(best)
    }

    /// The encrypted query/response round-trip against `cert`. Frames the padded, AEAD-sealed query,
    /// sends it (UDP, TCP on TC), then decrypts + authenticates the reply and strips padding. The
    /// returned bytes are opaque (the resolver runs `validate_response`). No qname logged (T20).
    async fn encrypted_exchange(
        &self,
        cert: &CachedCert,
        query_wire: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        // ★ PQDNSCrypt dispatch — an es-0x0003 cert routes to the X-Wing exchange; the classic
        // X25519 path below is byte-untouched for es-v1/v2 certs.
        //
        // ★ #97 — THE witness fork. Both counters are bumped HERE and nowhere else, so the census is
        // exact by construction: one increment per encrypted exchange, on the branch actually taken.
        // The bump precedes the await deliberately — it records the NEGOTIATED cipher (the cert is
        // already Ed25519-verified and es-selected at this point), not the exchange's success, so a
        // resolver that times out still truthfully reports which cryptography was chosen for it.
        if cert.es_version == ES_XWING_PQ {
            PQ_EXCHANGES.fetch_add(1, Ordering::Relaxed);
            return self.pq_encrypted_exchange(cert, query_wire).await;
        }
        CLASSIC_EXCHANGES.fetch_add(1, Ordering::Relaxed);

        // T15 — a FRESH CSPRNG 12-byte client-nonce half per query, never reused. The other 12 bytes
        // are zero (the resolver fills its half in the response nonce).
        let mut half_nonce = [0u8; HALF_NONCE_LEN];
        csprng_fill(&mut half_nonce)?;

        // A fresh ephemeral X25519 client key per exchange (forward secrecy; its pk is sent in-frame).
        let mut sk_bytes = [0u8; 32];
        csprng_fill(&mut sk_bytes)?;
        let client_secret = StaticSecret::from(sk_bytes);
        let client_pk = PublicKey::from(&client_secret);

        // X25519 → NaCl crypto_box shared key (HSalsa20/HChaCha20 of the raw point, per es-version).
        let resolver_pk = PublicKey::from(cert.resolver_pk);
        let shared_point = client_secret.diffie_hellman(&resolver_pk).to_bytes();
        let shared_key = derive_shared_key(cert.es_version, &shared_point)?;

        // RFC-8467 / DNSCrypt block padding (T21), then AEAD-seal under the full 24-byte nonce.
        let padded = pad_query(query_wire);
        let mut full_nonce = [0u8; FULL_NONCE_LEN];
        full_nonce[..HALF_NONCE_LEN].copy_from_slice(&half_nonce);
        let sealed = aead_seal(cert.es_version, &shared_key, &full_nonce, &padded)?;

        // Frame: <client-magic(8)><client-pk(32)><client-nonce-half(12)><AEAD(padded query)>.
        let mut frame = Vec::with_capacity(8 + 32 + HALF_NONCE_LEN + sealed.len());
        frame.extend_from_slice(&cert.client_magic);
        frame.extend_from_slice(client_pk.as_bytes());
        frame.extend_from_slice(&half_nonce);
        frame.extend_from_slice(&sealed);

        // ENCRYPTED user query: the reply's byte[2] is the resolver MAGIC, not a DNS TC bit (FIX 2), so
        // we accept the UDP reply and let `decrypt_response` validate magic + nonce echo + AEAD tag.
        // Slice 2: when a relay chain is configured, the encrypted frame is wrapped in the anonymized
        // envelope and sent to the FIRST relay; the resolver's encrypted reply comes back UNWRAPPED (the
        // relay passes it through verbatim — no envelope stripping on the reply, per the Go datapath).
        let reply = relayed_udp_then_tcp(
            &self.relays,
            &self.addr,
            &frame,
            ReplyKind::EncryptedDnsCrypt,
        )
        .await?;
        decrypt_response(cert.es_version, &shared_key, &half_nonce, &reply)
    }

    /// ★ PQDNSCrypt (es-0x0003) query/response round-trip — the X-Wing edition of
    /// [`Self::encrypted_exchange`], mirroring upstream `encryptPQ` (pq.go:214-259) with ONE deliberate
    /// divergence: a FRESH X-Wing encapsulation EVERY query. Upstream caches one (ciphertext, key) pair
    /// per network epoch and reuses it across queries (pq.go:242-250) — reused ciphertext makes every
    /// query in the epoch linkable to one client at the resolver. This file's classic path already
    /// diverged the same way (a per-QUERY ephemeral X25519 key where upstream reuses one keypair per
    /// network) — the per-query-ephemeral law, PQ edition: ML-KEM-768 encapsulation is microseconds
    /// against a network RTT, so unlinkability wins. For the same reason we never SEND resumption
    /// ("PQResume") queries — a reused ticket is the same linkability leak — but the response control
    /// block is still parsed + stripped (mandatory for a correct body; see [`pq_strip_control`]).
    ///
    /// Wire frame (fresh query, pq.go:253-257):
    /// `<client-magic(8)><x-wing ct(1120)><client-nonce-half(12)><XChaCha-secretbox(pq-padded query)>`
    /// — the shared key is HKDF-SHA256-bound to the SIGNED cert (see [`pq_derive_shared_key`]).
    async fn pq_encrypted_exchange(
        &self,
        cert: &CachedCert,
        query_wire: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        let pq = cert
            .pq
            .as_ref()
            .ok_or_else(|| TransportError::Exchange("PQ cert missing X-Wing material".into()))?;

        // T15 — fresh CSPRNG client-nonce half per query, exactly like the classic path.
        let mut half_nonce = [0u8; HALF_NONCE_LEN];
        csprng_fill(&mut half_nonce)?;

        // Per-query-ephemeral law, PQ edition: 64 FRESH CSPRNG bytes drive this query's encapsulation
        // (first 32 → ML-KEM-768, last 32 → the X25519 half; x-wing-0.1.0/src/lib.rs:108-128). Used
        // once, never cached — see the method doc for the upstream divergence.
        let mut eseed = [0u8; 64];
        csprng_fill(&mut eseed)?;

        let ek = XWingEncapsulationKey::try_from(pq.pk.as_slice())
            .map_err(|_| TransportError::Exchange("X-Wing encapsulation key invalid".into()))?;
        let (ct, kem_ss) = ek.encapsulate_deterministic(&eseed.into());

        // Bind the KEM shared secret to the SIGNED cert + THIS ciphertext (pq.go:76-86).
        let shared_key = pq_derive_shared_key(&kem_ss, &cert.client_magic, &pq.cert_context, &ct);

        // PQ padding floor is ONE block for a ciphertext-carrying query (pq.go:251) — the 1120-byte
        // KEM ciphertext dominates the frame, so MIN_PADDED would only waste mobile bytes.
        let padded = pq_pad(query_wire, PQ_FRESH_PAD_FLOOR);
        let mut full_nonce = [0u8; FULL_NONCE_LEN];
        full_nonce[..HALF_NONCE_LEN].copy_from_slice(&half_nonce);
        // The PQ AEAD is the SAME NaCl XChaCha20 secretbox as es-v2 (upstream seals PQ queries with
        // `xsecretbox.Seal`, pq.go:252 / crypto.go:233) — reuse the existing seal, no new cipher.
        let sealed = aead_seal(ES_XCHACHA, &shared_key, &full_nonce, &padded)?;

        // Frame: <client-magic(8)><x-wing ct(1120)><client-nonce-half(12)><AEAD(pq-padded query)>.
        let mut frame =
            Vec::with_capacity(8 + PQ_XWING_CT_LEN + HALF_NONCE_LEN + sealed.len());
        frame.extend_from_slice(&cert.client_magic);
        frame.extend_from_slice(&ct[..]);
        frame.extend_from_slice(&half_nonce);
        frame.extend_from_slice(&sealed);

        // Same reply law as the classic path: encrypted replies ride UDP as-is (FIX 2), the relay
        // chain wraps the frame verbatim (the envelope is payload-agnostic — a PQ frame relays
        // exactly like a classic one).
        let reply = relayed_udp_then_tcp(
            &self.relays,
            &self.addr,
            &frame,
            ReplyKind::EncryptedDnsCrypt,
        )
        .await?;
        pq_decrypt_response(&shared_key, &half_nonce, &reply)
    }
}

impl Transport for DnsCrypt {
    fn id(&self) -> &str {
        &self.id
    }

    /// ★ CP-Attribution — DNSCrypt is the namesake connectionless-UDP transport (the Beast's
    /// "first-ever UDP YeAH"): its winning live-forward RTT feeds the dashboard's UDP base_rtt + floor.
    fn is_udp_family(&self) -> bool {
        true
    }

    /// ★ G5 — surface the attached relay's display name (the query.log `relay` column). `None` when
    /// this transport rides direct or its relay was attached without a name (bare-stamp path).
    fn relay_name(&self) -> Option<&str> {
        self.relay_name.as_deref()
    }

    /// ★ 2.1.18-absorb (measurement honesty) — prime the cert cache OUTSIDE the pool's RTT
    /// stopwatch. `exchange` lazily pays the cert fetch (a full plaintext round-trip + Ed25519
    /// verify) on first contact / expiry; without this seam that setup time lands in the FIRST
    /// EWMA sample — the seed — mispricing the transport for its whole life (and rotation ranking
    /// consumes these EWMAs). Errors are swallowed by contract: the timed `exchange` right after
    /// re-runs `ensure_cert` (cache-hit if we succeeded, real error surfaced + recorded if not).
    fn warm_setup<'a>(&'a self) -> WarmFuture<'a> {
        Box::pin(async move {
            let _ = self.ensure_cert().await;
        })
    }

    fn exchange<'a>(&'a self, query_wire: &'a [u8]) -> ExchangeFuture<'a> {
        Box::pin(async move {
            let cert = self.ensure_cert().await?;
            self.encrypted_exchange(&cert, query_wire).await
        })
    }
}

// ---------------------------------------------------------------------------------------------------
// R2 — the protect-then-connect guard (the egress-loop invariant).
// ---------------------------------------------------------------------------------------------------
//
// Risk 2 of the de-InviZible tunnel spec: every upstream socket the resolver opens MUST call
// `VpnService.protect(fd)` on its fd BEFORE `connect()`/`sendto()`, or the upstream packet re-enters
// our own tun (the egress loop — the loop sees its own encrypted query, re-resolves it, sends it
// again, …). The trait [`crate::tunnel::ProtectCallback`] is defined in the tunnel module (task 1C);
// this module wires the CALL SITE (task 1E).
//
// The callback is a PROCESS-GLOBAL, set by `TunnelController::start` via [`install_protect_callback`].
// A process-global (not per-transport) is the right shape here: the transports are constructed in
// `resolver::configure` BEFORE the tunnel starts (the resolver is armed at VPN-establish time, R3),
// and held as `Arc<dyn Transport>` in the pool — there is no constructor argument that walks the
// callback into them. A `Mutex<Option<Arc<dyn ProtectCallback>>>` (not a `OnceLock`) so a VPN
// down/up cycle can clear + re-install it (the QUIC endpoints rebuild on that cycle, see doq/doh3).
//
// Host build (the `cargo test` / `cargo check` host): no VPN, the callback is NEVER installed, and
// [`protect_raw_fd`] is a no-op — the datapath is byte-identical to pre-1E. The fd extraction
// (`AsRawFd`) is unix-gated; the guard's call sites compile identically on both targets.

use crate::tunnel::ProtectCallback;

/// The process-global Risk-2 protect callback. `None` on the host build + before the tunnel wires the
/// Kotlin callback. `Mutex` (not `OnceLock`) so a VPN down/up cycle can swap/clear it (R2 rebuild).
/// How many times a resolver handed back a cert with a LOWER serial than the one it replaced.
///
/// A DNSCrypt serial identifies a key generation, and a regression means the resolver offered an
/// OLDER key than one this device already held. Benignly that is a resolver that reset its counter;
/// hostilely it is retired-key pinning — steering the client onto a key the operator has rotated
/// away from, and possibly lost control of.
///
/// Process-global rather than per-transport on purpose: the question an operator asks is "is
/// anything doing this to me", not "which of my upstreams did it in which epoch". A per-transport
/// breakdown would be a per-upstream behavioural fingerprint retained on device for no operational
/// gain (T20).
static CERT_SERIAL_REGRESSIONS: AtomicU64 = AtomicU64::new(0);

/// Reader for [`CERT_SERIAL_REGRESSIONS`]. Honest zero on a device that has never seen one, which
/// is the expected reading — this counter is an alarm, not a metric, and a non-zero value warrants
/// looking at the upstream rather than at this crate.
pub fn cert_serial_regressions() -> u64 {
    CERT_SERIAL_REGRESSIONS.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn reset_cert_serial_regressions_for_test() {
    CERT_SERIAL_REGRESSIONS.store(0, Ordering::Relaxed);
}

static PROTECT_CALLBACK: Mutex<Option<Arc<dyn ProtectCallback>>> = Mutex::new(None);

/// Install (or clear, on `None`) the process-global Risk-2 protect callback. Called by the tunnel
/// controller at start/stop — Kotlin's `vpnService.protect(fd)` reaches the resolver's upstream
/// sockets (DNSCrypt UDP/TCP, DoQ, DoH3) through this one global. Reentrancy-safe: a `Mutex` swap.
pub fn install_protect_callback(cb: Option<Arc<dyn ProtectCallback>>) {
    *PROTECT_CALLBACK.lock().unwrap_or_else(|e| e.into_inner()) = cb;
}

/// Whether a protect callback is currently armed. The QUIC transports consult this to decide whether
/// their endpoint's socket was protected at construction (and thus whether a VPN cycle needs a
/// rebuild). `false` on the host build + before the tunnel wires the callback.
pub fn protect_callback_installed() -> bool {
    PROTECT_CALLBACK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_some()
}

/// The Risk-2 guard: call `VpnService.protect(fd)` on `fd` BEFORE the upstream socket connects, or
/// fail-fast. No callback installed (host build / pre-wire) ⇒ `Ok(())` — the no-VPN path is
/// byte-identical to pre-1E. A `false` return ⇒ [`TransportError::Connect`] so the pool ladders to
/// the next transport (NEVER proceeds with an unprotected socket — the egress-loop invariant).
#[cfg(unix)]
fn protect_raw_fd(fd: i32) -> Result<(), TransportError> {
    let guard = PROTECT_CALLBACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref cb) = *guard {
        if !cb.protect_fd(fd) {
            return Err(TransportError::Connect(
                "vpn protect refused fd (egress-loop guard)".into(),
            ));
        }
    }
    Ok(())
}

/// Host-build no-op (no VPN on the cargo-test host; the callback is never installed). Kept as a
/// separate `#[cfg(not(unix))]` body so the call sites compile identically on both targets and the
/// fd extraction (`AsRawFd`) stays unix-only.
#[cfg(not(unix))]
fn protect_raw_fd(_fd: i32) -> Result<(), TransportError> {
    Ok(())
}

/// The protect-then-connect helper for any socket exposing a raw fd. Call this AFTER bind/creation
/// and BEFORE `connect()`/`sendto()`. On the host build it is a no-op (no VPN); on Android it calls
/// `vpnService.protect(fd)` through the installed callback and fail-fasts on `false`. Generic over
/// the socket type so it composes with both `tokio::net::UdpSocket` and `TcpSocket` (and `std::net`
/// sockets, for the QUIC endpoint's underlying UDP socket).
#[cfg(unix)]
fn protect_socket_before_connect<T: std::os::unix::io::AsRawFd>(
    sock: &T,
) -> Result<(), TransportError> {
    protect_raw_fd(sock.as_raw_fd())
}

/// Host-build counterpart (no fd extraction — `AsRawFd` is unix-only). The no-op keeps the call
/// sites identical across targets.
#[cfg(not(unix))]
fn protect_socket_before_connect<T>(_sock: &T) -> Result<(), TransportError> {
    Ok(())
}

/// Build a quinn-compatible UDP socket with its fd `VpnService.protect()`-ed ONCE at construction
/// (R2 for the QUIC transports — DoQ / DoH3). The quinn `Endpoint` multiplexes EVERY connection over
/// this ONE long-lived fd, so unlike DNSCrypt (which opens a fresh protected socket per exchange) the
/// QUIC transports protect ONCE here and rebuild when the VPN cycles (down/up). On the host build
/// this is a plain unprotected bind (no callback installed) — byte-identical to pre-1E.
///
/// Returns a non-blocking `std::net::UdpSocket` bound to an OS-assigned port, ready to hand to
/// `quinn::Endpoint::new`. The caller is expected to construct the `Endpoint` immediately (the socket
/// is useless unwrapped) and to call this AGAIN on a VPN down/up cycle (re-protect the new fd).
///
// REMOVED 2026-07 with the DEPRECATED `quic`/`doh3` transports: `new_protected_quic_socket`, which
// bound and VPN-protected the single UDP fd a `quinn::Endpoint` multiplexes over. Its only callers
// were doq.rs and doh3.rs. The R2 protect discipline itself is UNCHANGED and still applies to every
// remaining transport through `protect_socket_before_connect`.

// ---------------------------------------------------------------------------------------------------
// Network — UDP with a TCP-on-TC fallback. Bounded reads (T6); no qname ever logged (T20).
// ---------------------------------------------------------------------------------------------------

/// Whether the reply on a given `udp_then_tcp` exchange is a **plaintext DNS message** (so the DNS TC
/// truncation bit is meaningful) or a **DNSCrypt encrypted frame** (where byte[2] is NOT a header bit).
/// FIX 2: the TC→TCP retry must only fire on the plaintext path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplyKind {
    /// The plaintext cert-fetch TXT lookup — a real DNS message; honour the TC bit.
    PlaintextDns,
    /// An encrypted user query — the reply is `r6fnvWj8`-magic + nonce + AEAD; byte[2] is magic, not TC.
    EncryptedDnsCrypt,
}

// ---------------------------------------------------------------------------------------------------
// Anonymized-DNSCrypt relay (Slice 2 / T23) — the 0x81 relay-hop chain.
// ---------------------------------------------------------------------------------------------------

/// The anonymized-DNSCrypt relay envelope magic — the 10-byte header that prefixes every relayed
/// query. From the authoritative Go source (`dnscrypt-proxy/proxy.go:590`): `0xff` × 8 then `0x00 0x00`.
/// This is what a real anonymized-DNSCrypt relay recognizes to peel the envelope + forward to the
/// embedded resolver `IP:port`.
const RELAY_HEADER: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

/// Build ONE anonymized-DNSCrypt relay envelope around `payload`, addressed to `next_hop`. Slice 2
/// (T23). This is the byte-for-byte Rust mirror of the Go `prepareForRelay`
/// (`dnscrypt-proxy/proxy.go:589-597`):
///
/// ```text
///   [0xff × 8][0x00 0x00]   ← 10-byte anonymized header (RELAY_HEADER)
///   [ip.To16() × 16]        ← next-hop IP as a 16-byte IPv6 (IPv4 → ::ffff:a.b.c.d, RFC 4291)
///   [port BE × 2]           ← next-hop port, big-endian
///   [payload...]            ← the wrapped frame (encrypted query OR an inner relay envelope)
/// ```
///
/// `ip.To16()` mirrors Go's `net.IP.To16()`: an IPv4 address is emitted as its 16-byte IPv4-mapped
/// IPv6 representation (`::ffff:a.b.c.d`); a native IPv6 is emitted as-is. This is REQUIRED — a relay
/// parses the 16-byte field as IPv6, and an unmapped 4-byte IPv4 would shift every subsequent field.
/// Returns the wrapped bytes (the relay reads the header, dials the embedded `next_hop`, and forwards
/// `payload` to it; the relayed reply comes back UNWRAPPED).
fn wrap_for_relay(payload: &[u8], next_hop: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(RELAY_HEADER.len() + 16 + 2 + payload.len());
    out.extend_from_slice(&RELAY_HEADER);
    // ip.To16() — IPv4 → IPv4-mapped IPv6 (::ffff:a.b.c.d), IPv6 → as-is.
    out.extend_from_slice(&ip_to_ipv6_bytes(next_hop.ip()));
    out.extend_from_slice(&next_hop.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Emit an `IpAddr` as its 16-byte IPv6 representation, mirroring Go's `net.IP.To16()` used by the
/// authoritative `prepareForRelay`. An IPv4 address becomes its IPv4-mapped IPv6 form
/// (`::ffff:a.b.c.d`, RFC 4291 — `Ipv4Addr::to_ipv6_mapped`); an IPv6 address is emitted as-is. This
/// is load-bearing: the relay parses the field as a fixed 16-byte IPv6, so an unmapped IPv4 would
/// misalign the trailing port + payload.
fn ip_to_ipv6_bytes(ip: std::net::IpAddr) -> [u8; 16] {
    match ip {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

/// Wrap `payload` for a relay chain, returning the fully-wrapped wire bytes AND the address to dial
/// (the FIRST relay). Slice 2 (T23). Each envelope's embedded `next_hop` tells the relay that receives
/// it where to forward the payload. The FIRST relay is the DIAL target — its address is never embedded
/// (it is where the outer envelope is SENT); the embedded next-hops, outermost→innermost, are
/// `relays[1..]` then the resolver:
///
///   chain = [relay_a, relay_b]   (relay_a dialed first; relay_b is the next hop after relay_a)
///   resolver = self.addr
///
///   step 1: inner = wrap(payload, next_hop = resolver)   // envelope relay_b → resolver
///   step 2: outer = wrap(inner,   next_hop = relay_b)    // envelope relay_a → relay_b (DIALED at relay_a)
///
/// A one-element chain collapses to a single envelope with the RESOLVER embedded (the common
/// production case — the upstream Go proxy uses ONE relay per query, calling `prepareForRelay` ONCE
/// with the resolver addr). An empty chain returns the payload UNCHANGED and the resolver addr as the
/// dial target (the direct path, byte-identical to pre-Slice-2). Returns `(wire_bytes_to_send, dial_addr)`.
fn wrap_for_relay_chain(
    payload: &[u8],
    resolver: SocketAddr,
    relays: &[SocketAddr],
) -> (Vec<u8>, SocketAddr) {
    if relays.is_empty() {
        return (payload.to_vec(), resolver);
    }
    // Embed list, innermost-first: the resolver (innermost envelope) then relays[1..] in reverse so
    // the outermost envelope embeds relays[1] (the first relay's next-hop). relays[0] is the dial
    // target and is NOT embedded.
    let mut wire = wrap_for_relay(payload, resolver);
    for next_hop in relays[1..].iter().rev() {
        wire = wrap_for_relay(&wire, *next_hop);
    }
    (wire, relays[0])
}

/// The relay-aware dispatcher around [`udp_then_tcp`] (Slice 2). When `relays` is empty this is
/// byte-identical to `udp_then_tcp(resolver, payload, kind)` — the direct production path. When
/// `relays` is non-empty, the payload is wrapped in the anonymized envelope chain (addressed to the
/// resolver, dialed at the first relay) BEFORE send, and the reply is returned AS-IS (the relay passes
/// the resolver's reply back verbatim — no envelope stripping, per the Go datapath at `proxy.go:655`).
async fn relayed_udp_then_tcp(
    relays: &[SocketAddr],
    resolver: &SocketAddr,
    payload: &[u8],
    kind: ReplyKind,
) -> Result<Vec<u8>, TransportError> {
    let (wire, dial) = wrap_for_relay_chain(payload, *resolver, relays);
    udp_then_tcp(&dial, &wire, kind).await
}

/// ★ 2.1.18-absorb — the PQ cert-fetch lane: TCP-first, classic UDP+TC ladder as the fallback.
/// The relay-aware twin of [`relayed_udp_then_tcp`] with the lane order INVERTED: a PQ es-0x0003
/// cert answer (1320-byte cert + TXT framing) can never fit the classic 512-byte UDP ceiling
/// ([`build_txt_query`] sends no EDNS0 OPT), so UDP-first is either a guaranteed TC round-trip or a
/// silent fragment-drop hang on fragment-hostile paths. TCP (RFC 7766 length-prefixed) carries any
/// size deterministically. If TCP itself fails (dead port, filtered SYN), fall back to the classic
/// UDP+TC ladder — a classic-only resolver still answers there, and fail-open beats fail-closed for
/// a fetch whose authenticity is Ed25519-signed regardless of channel. The relay envelope is
/// transport-agnostic bytes (the Go datapath relays both lanes), so the wrapped wire rides TCP
/// unchanged — upstream 2.1.18 calls this out: "including when certificates are fetched through
/// Anonymized DNSCrypt relays".
async fn relayed_tcp_then_udp(
    relays: &[SocketAddr],
    resolver: &SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let (wire, dial) = wrap_for_relay_chain(payload, *resolver, relays);
    match tcp_exchange(&dial, &wire).await {
        Ok(reply) => Ok(reply),
        Err(_) => udp_then_tcp(&dial, &wire, ReplyKind::PlaintextDns).await,
    }
}

/// Send `payload` to `addr` over UDP, optionally falling back to TCP (2-byte length-prefixed, RFC
/// 7766) on truncation. Returns the raw reply bytes (≤ 64 KiB, T6).
///
/// FIX 2 — the TC (truncation) bit is a DNS **header** bit and is ONLY meaningful on the plaintext
/// cert-fetch path ([`ReplyKind::PlaintextDns`]). On an [`ReplyKind::EncryptedDnsCrypt`] reply the
/// first bytes are the resolver magic `r6fnvWj8`, so byte[2] is `0x66` (`'f'`) and `0x66 & 0x02 == 0x02`
/// is ALWAYS "set" — peeking it would force a redundant TCP re-query on EVERY encrypted reply (doubled
/// latency, and a hard failure where TCP is firewalled). So we honour TC only for `PlaintextDns`; an
/// encrypted UDP reply is accepted as-is and left for `decrypt_response` to validate (magic + nonce
/// echo + AEAD tag). A genuinely truncated/over-large encrypted answer surfaces as a decrypt/parse
/// failure, never a spurious TCP storm.
async fn udp_then_tcp(
    addr: &SocketAddr,
    payload: &[u8],
    kind: ReplyKind,
) -> Result<Vec<u8>, TransportError> {
    let udp_reply = udp_exchange(addr, payload).await?;
    if should_retry_over_tcp(kind, &udp_reply) {
        // TC set on a plaintext DNS reply — the answer is truncated; retry over TCP for the full
        // message. (NEVER taken on the encrypted path, whose byte[2] is the resolver magic.)
        return tcp_exchange(addr, payload).await;
    }
    Ok(udp_reply)
}

/// The TC→TCP decision, factored out so it is unit-testable without a socket (FIX 2). A TCP retry is
/// warranted ONLY when the reply is a plaintext DNS message ([`ReplyKind::PlaintextDns`]) whose header
/// TC bit (flags byte 2, `0x02`) is set. For an [`ReplyKind::EncryptedDnsCrypt`] reply, byte[2] is the
/// resolver magic (`r6fnvWj8`[2] == `'f'` == 0x66, and 0x66 & 0x02 == 0x02), so it is NEVER read as a
/// TC bit — the encrypted reply is accepted from UDP and validated by `decrypt_response` instead.
fn should_retry_over_tcp(kind: ReplyKind, reply: &[u8]) -> bool {
    kind == ReplyKind::PlaintextDns && reply.len() >= 3 && (reply[2] & 0x02) != 0
}

/// One UDP request/response. Binds an ephemeral local socket, sends `payload`, reads one datagram
/// (bounded at 64 KiB, T6). `connect` pins the peer so a spoofed off-path datagram from another source
/// is dropped by the OS.
///
/// R2 (task 1E): the fd is `VpnService.protect()`-ed AFTER bind and BEFORE `connect()`/`sendto()`.
/// On the host build this is a no-op (no VPN); on Android the installed callback calls
/// `vpnService.protect(fd)` and a `false` return fail-fasts to the next transport (egress-loop guard).
async fn udp_exchange(addr: &SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    use tokio::net::UdpSocket;
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| TransportError::Connect(format!("udp bind: {e}")))?;
    // R2 — protect the fd BEFORE connect()/sendto() (egress-loop invariant). MUST follow bind (the fd
    // does not exist before it) and MUST precede connect/send (the first upstream packet egresses at
    // send; UDP `connect` only sets the OS-side peer, no packet is sent — but protect-before-connect is
    // the safe order for both UDP and the TCP fallback below).
    protect_socket_before_connect(&sock)?;
    sock.connect(addr)
        .await
        .map_err(|e| TransportError::Connect(format!("udp connect: {e}")))?;
    sock.send(payload)
        .await
        .map_err(|e| TransportError::Exchange(format!("udp send: {e}")))?;
    let mut buf = vec![0u8; MAX_RESPONSE];
    let n = sock
        .recv(&mut buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("udp recv: {e}")))?;
    buf.truncate(n);
    Ok(buf)
}

/// One TCP request/response, DNS-over-TCP framed (a 2-byte big-endian length prefix on the request and
/// on the reply, RFC 7766). The reply length prefix is bounded at 64 KiB (T6) before allocating.
///
/// R2 (task 1E): the socket is built explicitly via [`tokio::net::TcpSocket`] (NOT `TcpStream::connect`,
/// which is atomic — socket+bind+connect in one call and so cannot be protected before the SYN
/// egresses) so its fd can be `VpnService.protect()`-ed BEFORE `connect()`. The DNSCrypt TCP path is
/// only ever the cert-fetch plaintext fallback (the encrypted exchange is UDP-first), so this is the
/// rare path — but it still MUST NOT egress-loop when the VPN is up.
async fn tcp_exchange(addr: &SocketAddr, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpSocket, TcpStream};
    // Build the socket explicitly so the fd exists BEFORE connect(). `TcpStream::connect` is atomic
    // (socket+bind+connect) and would send the SYN before protect() could run — an egress loop on the
    // first cert-fetch TCP fallback under VPN.
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| TransportError::Connect(format!("tcp socket: {e}")))?;
    // R2 — protect the fd BEFORE connect() sends the SYN (egress-loop invariant).
    protect_socket_before_connect(&socket)?;
    let mut stream: TcpStream = socket
        .connect(*addr)
        .await
        .map_err(|e| TransportError::Connect(format!("tcp connect: {e}")))?;

    let len = u16::try_from(payload.len())
        .map_err(|_| TransportError::Exchange("tcp payload > 64KiB".into()))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp write len: {e}")))?;
    stream
        .write_all(payload)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp write: {e}")))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp read len: {e}")))?;
    let reply_len = u16::from_be_bytes(len_buf) as usize;
    if reply_len == 0 || reply_len > MAX_RESPONSE {
        return Err(TransportError::BadResponse(
            "tcp reply length out of bounds".into(),
        ));
    }
    let mut buf = vec![0u8; reply_len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| TransportError::Exchange(format!("tcp read: {e}")))?;
    Ok(buf)
}

/// Current wall-clock seconds since the unix epoch (saturating to 0 before 1970 — never panics). T14
/// compares cert `ts_start..ts_end` against this.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------------
// Cert fetch + T14 verification (Ed25519-verify vs the stamp pk, window, highest es_version).
// ---------------------------------------------------------------------------------------------------

/// One DNSCrypt cert's signed payload (everything after magic+version+`<signature>`). The Ed25519
/// signature covers exactly `resolver_pk || client_magic || serial || ts_start || ts_end || extensions`
/// — i.e. the bytes from offset 72 to the end of the TXT record.
struct ParsedCert {
    /// The UNSIGNED `es_version` header (bytes[4..6]). NOT inside the Ed25519-signed region, so an
    /// on-path attacker can flip it. FIX 2: it is NOT trusted to route the cipher — only sanity-checked
    /// for consistency against the SIGNED `client_magic`. The cipher is bound to `client_magic`.
    es_version: u16,
    resolver_pk: [u8; 32],
    /// The SIGNED (Ed25519-covered) client-magic (bytes[104..112]). FIX 2: this, not `es_version`,
    /// authoritatively identifies the cert/version the provider published; cipher is routed by it.
    client_magic: [u8; 8],
    /// The SIGNED serial (bytes[112..116], big-endian u32). FIX 3: freshness selector.
    serial: u32,
    /// Validity window start (bytes[116..120]), widened to `u64` for the Y2106-safe compare (FIX 4).
    ts_start: u64,
    /// Validity window end (bytes[120..124]), widened to `u64` for the Y2106-safe compare (FIX 4).
    ts_end: u64,
    /// The 64-byte Ed25519 signature (bytes 8..72 of the cert).
    signature: [u8; 64],
    /// The signed region (bytes 72..end of the cert): the bytes the signature covers.
    signed: Vec<u8>,
    /// ★ PQDNSCrypt — `Some` iff this is a valid es-0x0003 cert (1320+ bytes, exact signed profile
    /// extension). For a PQ cert `resolver_pk` is a zero placeholder (the real key is the 1216-byte
    /// X-Wing pk in here) and the classic-offset fields above are read from the PQ offsets instead.
    pq: Option<PqCertMaterial>,
}

/// Parse a DNSCrypt v2 certificate from its raw bytes. Layout (big-endian fields):
/// ```text
///   [0..4]   cert magic         "DNSC"
///   [4..6]   es_version         (1 = XSalsa20-Poly1305, 2 = XChaCha20-Poly1305)
///   [6..8]   protocol minor ver (ignored)
///   [8..72]  Ed25519 signature  (64 bytes) — over bytes [72..]
///   [72..104]  resolver short-term X25519 public key (32 bytes)
///   [104..112] client-magic     (8 bytes)
///   [112..116] serial           (u32, ignored here)
///   [116..120] ts_start         (u32, unix seconds)
///   [120..124] ts_end           (u32, unix seconds)
///   [124..]    extensions       (optional; part of the signed region)
/// ```
/// Every read is bounds-checked: a short/garbled cert is `None`, never a panic.
fn parse_cert(bytes: &[u8]) -> Option<ParsedCert> {
    if bytes.len() < 124 {
        return None;
    }
    if bytes[0..4] != CERT_MAGIC {
        return None;
    }
    let es_version = u16::from_be_bytes([bytes[4], bytes[5]]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[8..72]);

    // The signed region is everything from offset 72 onward (resolver_pk .. end-of-extensions).
    let signed = bytes[72..].to_vec();

    // ★ PQDNSCrypt — does this cert carry the SIGNED PQ profile extension at the fixed PQ offset?
    // (Exact 12-byte match, upstream dnscrypt_certs.go:140-144 — the extension pins ext-version, the
    // es-version ECHO, KDF, AEAD, and both key sizes, all inside the Ed25519-signed region.)
    let has_pq_profile = bytes.len() >= PQ_CERT_LEN && bytes[1308..1320] == PQ_PROFILE_EXT;

    if es_version == ES_XWING_PQ {
        // A PQ-claiming header without the signed PQ profile at the PQ offset is garbage/tampered.
        if !has_pq_profile {
            return None;
        }
        // PQ layout (pq.go / dnscrypt_certs.go:139-145): pk [72..1288], client-magic [1288..1296],
        // serial [1296..1300], ts_start [1300..1304], ts_end [1304..1308], extensions [1308..1320].
        let mut client_magic = [0u8; 8];
        client_magic.copy_from_slice(&bytes[1288..1296]);
        let serial = u32::from_be_bytes([bytes[1296], bytes[1297], bytes[1298], bytes[1299]]);
        let ts_start = u32::from_be_bytes([bytes[1300], bytes[1301], bytes[1302], bytes[1303]]) as u64;
        let ts_end = u32::from_be_bytes([bytes[1304], bytes[1305], bytes[1306], bytes[1307]]) as u64;
        return Some(ParsedCert {
            es_version,
            // Zero placeholder — the real peer key is the 1216-byte X-Wing pk in `pq`. All-zero is
            // an invalid X25519 point, so nothing can accidentally treat a PQ cert as classic.
            resolver_pk: [0u8; 32],
            client_magic,
            serial,
            ts_start,
            ts_end,
            signature,
            signed,
            pq: Some(PqCertMaterial {
                pk: bytes[72..72 + PQ_XWING_PK_LEN].to_vec(),
                cert_context: build_pq_cert_context(bytes),
            }),
        });
    }

    // ★ FIX 2, PQ edition (flipped-header downgrade fingerprint) — a cert whose SIGNED bytes carry the
    // exact PQ profile extension but whose UNSIGNED header claims a classic es-version is a PQ cert
    // with a flipped header: parsing it as classic would read 32 bytes of the X-Wing pk as an X25519
    // key and X-Wing pk bytes as serial/timestamps — validly signed garbage. REJECT on the signed
    // evidence. (Upstream only ext-checks when the header says PQ, dnscrypt_certs.go:139-144; anchoring
    // the check on the SIGNED profile instead is this file's FIX 2 posture — route by signed material.)
    if has_pq_profile {
        return None;
    }

    let mut resolver_pk = [0u8; 32];
    resolver_pk.copy_from_slice(&bytes[72..104]);
    let mut client_magic = [0u8; 8];
    client_magic.copy_from_slice(&bytes[104..112]);
    // FIX 3 — serial (bytes[112..116], big-endian u32), inside the signed region; used as the
    // freshness selector in `select_best_cert`.
    let serial = u32::from_be_bytes([bytes[112], bytes[113], bytes[114], bytes[115]]);
    // FIX 4 (Y2106) — widen the on-wire u32 timestamps to u64 so the window compare never narrows
    // `now` to u32 (which would wrap in 2106).
    let ts_start = u32::from_be_bytes([bytes[116], bytes[117], bytes[118], bytes[119]]) as u64;
    let ts_end = u32::from_be_bytes([bytes[120], bytes[121], bytes[122], bytes[123]]) as u64;

    Some(ParsedCert {
        es_version,
        resolver_pk,
        client_magic,
        serial,
        ts_start,
        ts_end,
        signature,
        signed,
        pq: None,
    })
}

/// ★ Build the PQ HKDF cert-binding context (upstream `pqCertContext`, pq.go:59-73): the domain label
/// then EVERY signed field of the 1320-byte cert, in cert order. The derived shared key is thereby
/// bound to the exact signed certificate — a swapped pk, serial, window, or extension changes the key
/// and the resolver's decrypt fails, closing any mix-and-match splice across certs.
fn build_pq_cert_context(cert: &[u8]) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(PQ_CONTEXT_LABEL.len() + 2 + 2 + PQ_XWING_PK_LEN + 8 + 4 + 4 + 4 + 12);
    ctx.extend_from_slice(PQ_CONTEXT_LABEL); // "DNSCrypt-PQ-v1"
    ctx.extend_from_slice(&cert[4..6]); // es-version (header echo — the signed ext pins it too)
    ctx.extend_from_slice(&cert[6..8]); // protocol-minor-version
    ctx.extend_from_slice(&cert[72..1288]); // resolver X-Wing pk
    ctx.extend_from_slice(&cert[1288..1296]); // client-magic
    ctx.extend_from_slice(&cert[1296..1300]); // serial
    ctx.extend_from_slice(&cert[1300..1304]); // ts-start
    ctx.extend_from_slice(&cert[1304..1308]); // ts-end
    ctx.extend_from_slice(&cert[1308..1320]); // extensions (the PQ profile)
    ctx
}

/// The es_version a given client_magic's published cert is bound to, established from the SIGNED
/// evidence (FIX 2). The resolver routes the cipher by the client-magic the client sends — which is
/// inside the Ed25519-signed region (bytes[104..112]) — so this is the authoritative cipher selector,
/// NOT the unsigned `es_version` header (bytes[4..6]) an on-path attacker can flip.
struct VerifiedCert {
    es_version: u16,
    resolver_pk: [u8; 32],
    client_magic: [u8; 8],
    serial: u32,
    ts_end: u64,
    /// ★ PQ material carried through verification (`Some` iff es-0x0003; the parse pairs them).
    pq: Option<PqCertMaterial>,
}

/// Is `now` inside the cert validity window `[ts_start, ts_end)`? FIX 4 (Y2106) — ALL THREE values are
/// `u64`, so the compare never narrows `now` to `u32`. The old inline check did `(now as u32) <
/// ts_start`, which WRAPS once `now` passes 2^32 (year 2106): a current `now` collapses to a tiny value
/// and a long-past `ts_start` then reads as "in the future", silently mis-classifying the window. With
/// a u64 compare a 2106-era `now` is correctly ordered against the window. (On-wire ts_* are u32 today,
/// so this is hardening — but the narrowing is a latent foot-gun the moment those widen.)
fn cert_in_window(now: u64, ts_start: u64, ts_end: u64) -> bool {
    now >= ts_start && now < ts_end
}

/// Among the certs the resolver returned, pick the BEST one (T14): Ed25519-verify the signed region
/// against `provider_pk`, require `ts_start <= now < ts_end`, require a known es_version, and return
/// the freshest of the highest valid es_version. `None` if not a single cert is valid.
///
/// FIX 2 (cipher-downgrade) — the cipher is bound to the SIGNED `client_magic`, never to the unsigned
/// `es_version` header. The header is NOT in the Ed25519-signed region, so an on-path attacker can flip
/// es-2→es-1 and `verify_strict` still passes; routing the cipher off it would silently downgrade
/// XChaCha20→XSalsa20. We defend two ways, both anchored on the signed `client_magic`:
///   (a) NEVER DOWNGRADE across the response: we keep the HIGHEST validly-signed es_version present.
///   (b) PER-MAGIC CONSISTENCY: the signed `client_magic` is the resolver's routing key, unique per
///       published (cert, version). If a validly-signed es-2 cert exists, an attacker's es-1-claiming
///       copy reuses signed key material the provider published at es-2 — a downgrade fingerprint — so
///       we reject any cert whose unsigned es_version is LOWER than the highest validly-signed
///       es_version that shares its signed `resolver_pk` (the X25519 key the flip cannot change). A
///       genuine es-2 cert whose es_version byte is flipped to 1 thus loses to / is overridden by its
///       own signed es-2 key material and is never used to seal XSalsa.
///
/// FIX 3 (freshness) — among validly-signed, in-window certs of EQUAL es_version, the HIGHEST `serial`
/// wins (dnscrypt-proxy semantics), with `ts_end` as a secondary tiebreak. This defeats a hostile
/// resolver pinning a retired (lower-serial) key by listing it last/first.
fn select_best_cert(
    certs: &[Vec<u8>],
    provider_pk: &[u8; 32],
    now: u64,
    pq_enabled: bool,
) -> Option<CachedCert> {
    let vk = VerifyingKey::from_bytes(provider_pk).ok()?;

    // Pass 1 — collect every validly-signed, in-window cert we can actually speak.
    let mut verified: Vec<VerifiedCert> = Vec::new();
    for raw in certs {
        let cert = match parse_cert(raw) {
            Some(c) => c,
            None => continue,
        };
        // Only es-versions we can actually speak. ★ es-0x0003 (X-Wing PQ) is spoken iff the
        // `pqdnscrypt` gate is ON (upstream dnscrypt_certs.go:124-126: a disabled toggle skips the PQ
        // cert entirely and the classic certs compete on their own).
        if cert.es_version != ES_XCHACHA
            && cert.es_version != ES_XSALSA
            && !(cert.es_version == ES_XWING_PQ && pq_enabled)
        {
            continue;
        }
        // T14 — Ed25519 verify the signed region against the stamp's provider pk (strict: rejects a
        // malleable/small-order signature). A tampered cert fails here and is skipped.
        let sig = Signature::from_bytes(&cert.signature);
        if vk.verify_strict(&cert.signed, &sig).is_err() {
            continue;
        }
        // T14 — enforce the validity window. FIX 4 (Y2106): the compare is u64 vs u64 end-to-end.
        if !cert_in_window(now, cert.ts_start, cert.ts_end) {
            continue;
        }
        verified.push(VerifiedCert {
            es_version: cert.es_version,
            resolver_pk: cert.resolver_pk,
            client_magic: cert.client_magic,
            serial: cert.serial,
            ts_end: cert.ts_end,
            pq: cert.pq,
        });
    }

    // FIX 2 — the highest validly-signed es_version bound to each SIGNED routing key (`resolver_pk`).
    // The resolver_pk is the X25519 short-term key; a flipped unsigned `es_version` header cannot change
    // it (it is in the signed region). A cert that CLAIMS a lower es_version than its own signed key
    // material was validly published at is a downgrade fingerprint → it is dropped below. This catches
    // the PAIRED downgrade (genuine es-2 + an injected es-1 copy reusing the es-2 signed key material).
    let max_es_for_key = |rpk: &[u8; 32]| -> u16 {
        verified
            .iter()
            .filter(|v| &v.resolver_pk == rpk)
            .map(|v| v.es_version)
            .max()
            .unwrap_or(0)
    };

    // Pass 2 — pick the best: highest es_version (never downgrade), then highest serial (freshest),
    // then latest ts_end. Skip any cert that is a per-key downgrade (FIX 2, paired case).
    //
    // ★ PQ note — es-major ordering means a valid es-0x0003 cert ALWAYS beats a classic cert, even a
    // fresher-serial one. Upstream orders serial-major with a construction tiebreak
    // (dnscrypt_certs.go:189-200), so there a higher-serial CLASSIC cert can beat the PQ cert; ours
    // cannot downgrade to classic while a valid PQ cert is on offer — the "never downgrade" law
    // extended to the PQ boundary. PQ certs ride the same guard loop: their `resolver_pk` is the
    // all-zero placeholder, which no genuine classic cert can share (an all-zero X25519 pk is not a
    // usable key), so the per-key fingerprint never cross-fires between the PQ and classic pools.
    let mut best: Option<&VerifiedCert> = None;
    for cand in &verified {
        if cand.es_version < max_es_for_key(&cand.resolver_pk) {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => {
                // never downgrade es_version; then FIX 3 freshness (serial), then ts_end.
                (cand.es_version, cand.serial, cand.ts_end) > (b.es_version, b.serial, b.ts_end)
            }
        };
        if better {
            best = Some(cand);
        }
    }

    let best = best?;

    // FIX 2 (LONE downgrade) — the decisive bind to the SIGNED region for the single-cert case. The
    // `es_version` byte (bytes[4..6]) is UNSIGNED, so an on-path attacker can flip a genuine es-2
    // (XChaCha20-Poly1305) cert's header to es-1 (XSalsa20-Poly1305) — the WEAKER legacy cipher — and
    // `verify_strict` STILL passes. With only that one flipped cert in the response, the per-key guard
    // above cannot see the original es-2, so trusting the header would SILENTLY DOWNGRADE the cipher.
    //
    // This fork's es-2 (XChaCha20) is THE modern default (the cert/file docs: "never downgrade"). So we
    // REFUSE to seal under the weaker XSalsa20 chosen via an UNSIGNED header: a selected es-1 cert is
    // rejected as an un-authenticated downgrade. (The es-1 seal/open code stays intact for a future
    // cross-fetch-pinned legacy opt-in, where the version is bound out-of-band rather than read from a
    // flippable header.) Net effect: a flipped es-2→es-1 cert is REJECTED, never silently downgraded.
    if best.es_version == ES_XSALSA {
        return None;
    }

    Some(CachedCert {
        es_version: best.es_version,
        resolver_pk: best.resolver_pk,
        client_magic: best.client_magic,
        serial: best.serial,
        ts_end: best.ts_end,
        // ★ PQ material rides the cache (`Some` iff es-0x0003). Clone: `best` borrows `verified`;
        // one ~2.5 KiB copy per cert (re)fetch, never per query.
        pq: best.pq.clone(),
    })
}

/// Build a plaintext DNS TXT query for `provider_name` (qtype 16 = TXT). A small standalone builder so
/// the cert fetch needs nothing from `dns.rs` (which only builds A/AAAA queries). RD=1, one question.
fn build_txt_query(provider_name: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(provider_name.len() + 18);
    // A fixed, non-secret transaction id is fine for the cert fetch (the answer is Ed25519-signed; we
    // do not run `validate_response` on the cert path). Keep it deterministic for testability.
    msg.extend_from_slice(&0u16.to_be_bytes()); // id
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in provider_name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        let n = bytes.len().min(63);
        msg.push(n as u8);
        msg.extend_from_slice(&bytes[..n]);
    }
    msg.push(0); // root label
    msg.extend_from_slice(&16u16.to_be_bytes()); // QTYPE = TXT
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    msg
}

/// Extract the cert blobs from a DNS TXT response: walk the answer records, and for each TXT record
/// concatenate its length-prefixed character-strings into one blob (a DNSCrypt cert TXT is a single
/// `<len><bytes...>` string, but joining is correct + bounds-safe). Returns every TXT RDATA blob so
/// `select_best_cert` can pick the best. `None` only on a structurally broken header.
///
/// This is a deliberately small, bounds-checked walker (no compression-pointer following needed for
/// the owner names, which are simple uncompressed labels in practice; a pointer just ends the name).
/// It never panics and never reads out of bounds — a malformed record stops the walk.
fn parse_cert_txts(response: &[u8]) -> Option<Vec<Vec<u8>>> {
    if response.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
    let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;

    let mut pos = 12usize;
    // Skip the question section(s).
    for _ in 0..qdcount {
        pos = skip_name(response, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
        if pos > response.len() {
            return None;
        }
    }

    let mut out = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(response, pos)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 fixed bytes.
        if pos + 10 > response.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
        let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
        let rdata_at = pos + 10;
        let rdata_end = rdata_at.checked_add(rdlength)?;
        if rdata_end > response.len() {
            return None;
        }
        if rtype == 16 {
            // TXT — concatenate the length-prefixed character-strings inside RDATA.
            let mut blob = Vec::with_capacity(rdlength);
            let mut p = rdata_at;
            while p < rdata_end {
                let slen = response[p] as usize;
                let s = p + 1;
                let e = s.checked_add(slen)?;
                if e > rdata_end {
                    return None;
                }
                blob.extend_from_slice(&response[s..e]);
                p = e;
            }
            out.push(blob);
        }
        pos = rdata_end;
    }
    Some(out)
}

/// Advance past a DNS name starting at `pos`, returning the position just AFTER it. Handles a
/// compression pointer (2 bytes, ends the name) and uncompressed labels. Bounds-checked; `None` on a
/// label/pointer that runs off the end. (We do not need the decoded name on the cert path — only its
/// length — so this is a skip, not a decode.)
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 2-byte compression pointer terminates the name in-stream.
            if pos + 2 > buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if len & 0xC0 != 0 {
            return None; // reserved label-type bits set
        }
        pos = pos.checked_add(1 + len)?;
        if pos > buf.len() {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Crypto — X25519 → NaCl crypto_box shared key, AEAD seal/open, RFC-8467 padding, CSPRNG nonce.
// ---------------------------------------------------------------------------------------------------

/// Fill `dst` with cryptographically secure random bytes via `getrandom` (OS CSPRNG). T15: the client
/// nonce is sourced HERE, so a `getrandom` failure is surfaced (never a zero/weak nonce silently).
fn csprng_fill(dst: &mut [u8]) -> Result<(), TransportError> {
    getrandom::getrandom(dst).map_err(|e| TransportError::Exchange(format!("csprng: {e}")))
}

/// Derive the NaCl `crypto_box` shared key from the raw X25519 shared point, per es-version. For es v1
/// (XSalsa20-Poly1305) this is `crypto_box_beforenm` = `HSalsa20(point, 0₁₆)`; for es v2
/// (XChaCha20-Poly1305) it is `HChaCha20(point, 0₁₆)`. The `crypto_secretbox` NaCl ciphers
/// (`XSalsa20Poly1305` / `XChaCha20Poly1305`) then take this 32-byte key and the full 24-byte nonce
/// directly — the secretbox layer internally re-derives its own HSalsa20/HChaCha20 subkey from the
/// nonce prefix, exactly as libsodium `crypto_box_*` composes `beforenm` with `crypto_secretbox`.
fn derive_shared_key(es_version: u16, point: &[u8; 32]) -> Result<[u8; 32], TransportError> {
    match es_version {
        ES_XCHACHA => Ok(hchacha20(point, &[0u8; 16])),
        ES_XSALSA => Ok(hsalsa20(point, &[0u8; 16])),
        v => Err(TransportError::Exchange(format!("unknown es_version {v}"))),
    }
}

/// Poly1305 tag length DNSCrypt prepends in combined (NaCl `crypto_box`) mode.
const AEAD_TAG_LEN: usize = 16;

/// AEAD-seal `plaintext` (the padded query) under `key` + the full 24-byte `nonce`, per es-version.
///
/// Output is **always** `tag(16) || ciphertext`, the NaCl `crypto_secretbox` / DNSCrypt combined-mode
/// layout that real resolvers expect, with the Poly1305 MAC over the CIPHERTEXT ONLY (no RFC-8439
/// length block, no AAD). Both es-versions go through RustCrypto's `crypto_secretbox`, so the seal is
/// byte-for-byte libsodium `crypto_secretbox_*` for each:
///   * es-v2 (XChaCha20-Poly1305): `crypto_secretbox::XChaCha20Poly1305` — the libsodium XChaCha20
///     variant. (FIX 1: this replaces the old `chacha20poly1305 0.10.1` path, whose IETF Poly1305 MAC
///     also hashed a length block → a WRONG tag VALUE for the NaCl construction.)
///   * es-v1 (XSalsa20-Poly1305): `crypto_secretbox::XSalsa20Poly1305` — classic NaCl secretbox.
///
/// `crypto_secretbox`'s `Aead::encrypt` PREPENDS the tag, so no manual assembly is needed.
fn aead_seal(
    es_version: u16,
    key: &[u8; 32],
    nonce: &[u8; FULL_NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    match es_version {
        ES_XCHACHA => {
            let cipher = NaclXChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::Exchange("xchacha key".into()))?;
            // NaCl secretbox: tag||ciphertext, Poly1305 over the ciphertext only (no length block).
            cipher
                .encrypt(nonce.into(), plaintext)
                .map_err(|_| TransportError::Exchange("xchacha seal".into()))
        }
        ES_XSALSA => {
            let cipher = NaclXSalsa20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::Exchange("xsalsa key".into()))?;
            // NaCl secretbox: tag||ciphertext, Poly1305 over the ciphertext only (no length block).
            cipher
                .encrypt(nonce.into(), plaintext)
                .map_err(|_| TransportError::Exchange("xsalsa seal".into()))
        }
        v => Err(TransportError::Exchange(format!("unknown es_version {v}"))),
    }
}

/// AEAD-open a DNSCrypt combined-mode box `tag(16) || ciphertext` under `key` + the full 24-byte
/// `nonce`, per es-version. A tampered byte fails the Poly1305 tag → `Err` (never a panic). The input
/// layout is always TAG-PREPENDED with the MAC over the ciphertext only (NaCl/DNSCrypt), the mirror of
/// [`aead_seal`]. Both es-versions open through `crypto_secretbox`, whose `Aead::decrypt` already reads
/// `tag||ciphertext` and authenticates the ciphertext alone (no length block) — so it is the exact
/// inverse of our NaCl seal for each version.
fn aead_open(
    es_version: u16,
    key: &[u8; 32],
    nonce: &[u8; FULL_NONCE_LEN],
    boxed: &[u8],
) -> Result<Vec<u8>, TransportError> {
    match es_version {
        ES_XCHACHA => {
            let cipher = NaclXChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::Exchange("xchacha key".into()))?;
            cipher
                .decrypt(nonce.into(), boxed)
                .map_err(|_| TransportError::BadResponse("xchacha tag".into()))
        }
        ES_XSALSA => {
            let cipher = NaclXSalsa20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::Exchange("xsalsa key".into()))?;
            cipher
                .decrypt(nonce.into(), boxed)
                .map_err(|_| TransportError::BadResponse("xsalsa tag".into()))
        }
        v => Err(TransportError::Exchange(format!("unknown es_version {v}"))),
    }
}

/// Decrypt + authenticate a DNSCrypt resolver reply, then strip padding → the inner DNS wire bytes.
///
/// Layout of an encrypted reply:
/// ```text
///   [0..8]   resolver magic  "r6fnvWj8"
///   [8..20]  client nonce    (the 12-byte half we sent — MUST echo)
///   [20..32] server nonce    (the resolver's 12-byte half)
///   [32..]   AEAD(padded response) under the SAME shared key + the full 24-byte nonce
/// ```
/// Verifies the magic, the client-nonce echo, AEAD-opens (tampered → `Err`, never a panic), unpads.
fn decrypt_response(
    es_version: u16,
    shared_key: &[u8; 32],
    client_half: &[u8; HALF_NONCE_LEN],
    reply: &[u8],
) -> Result<Vec<u8>, TransportError> {
    // 8 (magic) + 24 (nonce) + 16 (Poly1305 tag) = 48-byte minimum.
    if reply.len() < 8 + FULL_NONCE_LEN + AEAD_TAG_LEN {
        return Err(TransportError::BadResponse("reply too short".into()));
    }
    if reply[0..8] != RESOLVER_MAGIC {
        return Err(TransportError::BadResponse("bad resolver magic".into()));
    }
    // The first 12 bytes of the reply nonce MUST echo the client nonce we sent (anti off-path).
    if reply[8..8 + HALF_NONCE_LEN] != client_half[..] {
        return Err(TransportError::BadResponse(
            "client nonce not echoed".into(),
        ));
    }
    let mut full_nonce = [0u8; FULL_NONCE_LEN];
    full_nonce.copy_from_slice(&reply[8..8 + FULL_NONCE_LEN]);
    let ciphertext = &reply[8 + FULL_NONCE_LEN..];

    let padded = aead_open(es_version, shared_key, &full_nonce, ciphertext)?;
    unpad_response(padded).ok_or_else(|| TransportError::BadResponse("padding malformed".into()))
}

/// RFC-8467 / DNSCrypt block padding (T21): append `0x80` then `0x00` bytes until the TOTAL plaintext
/// length is at least [`MIN_PADDED`] AND a multiple of [`PAD_BLOCK`]. This is the ISO/IEC 7816-4
/// padding DNSCrypt mandates so the encrypted query length leaks no information below the block.
fn pad_query(query: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len() + PAD_BLOCK);
    out.extend_from_slice(query);
    out.push(0x80);
    // Round up to MIN_PADDED first, then to the next PAD_BLOCK multiple.
    let mut target = out.len();
    if target < MIN_PADDED {
        target = MIN_PADDED;
    }
    if target % PAD_BLOCK != 0 {
        target += PAD_BLOCK - (target % PAD_BLOCK);
    }
    out.resize(target, 0x00);
    out
}

/// Reverse [`pad_query`]: strip trailing `0x00` bytes back to the single `0x80` delimiter, then drop
/// it. Returns the original plaintext, or `None` if the padding is malformed (no `0x80` found, or only
/// zeros) — a tamper that survives the AEAD tag (it can't) would still be caught here.
///
/// D38 — IN-PLACE: `aead_open` already returns an OWNED `Vec`, so the unpad TRUNCATES it instead of
/// memcpying the full plaintext (was `padded[..i-1].to_vec()` — a needless ≤64 KiB copy per encrypted
/// exchange). Zero-copy on the hottest decrypt edge; the walk itself is unchanged.
fn unpad_response(mut padded: Vec<u8>) -> Option<Vec<u8>> {
    // Walk back over the trailing 0x00 fill to the 0x80 delimiter.
    let mut i = padded.len();
    while i > 0 && padded[i - 1] == 0x00 {
        i -= 1;
    }
    if i == 0 || padded[i - 1] != 0x80 {
        return None;
    }
    padded.truncate(i - 1);
    Some(padded)
}

// ---------------------------------------------------------------------------------------------------
// ★ PQDNSCrypt (es-0x0003) — the X-Wing key schedule + framing helpers. Every derivation mirrors
// upstream pq.go by measured offset; the Appendix-3 draft vectors in the test corpus pin the bytes.
// ---------------------------------------------------------------------------------------------------

/// ★ Derive the PQ per-query shared key (upstream `pqDeriveSharedKey`, pq.go:76-86):
/// `HKDF-SHA256(salt = es-version(2) || client-magic(8), ikm = kem-ss, info = cert-context || ct)`.
/// The salt binds the key to the negotiated es + the SIGNED routing magic; the info binds it to the
/// exact signed cert AND this query's ciphertext — no byte of the exchange is outside the schedule.
fn pq_derive_shared_key(
    kem_ss: &[u8],
    client_magic: &[u8; 8],
    cert_context: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    let mut salt = [0u8; 10];
    salt[0..2].copy_from_slice(&ES_XWING_PQ.to_be_bytes());
    salt[2..10].copy_from_slice(client_magic);

    let mut info = Vec::with_capacity(cert_context.len() + ct.len());
    info.extend_from_slice(cert_context);
    info.extend_from_slice(ct);

    let hk = Hkdf::<Sha256>::new(Some(&salt), kem_ss);
    let mut okm = [0u8; 32];
    // Infallible by construction: `expand` errs only when the requested length exceeds 255×32 bytes
    // (RFC 5869); 32 bytes can never trip it, so this never panics on the datapath.
    hk.expand(&info, &mut okm)
        .expect("32-byte HKDF-SHA256 output is always within the RFC 5869 bound");
    okm
}

/// ★ PQ padding (upstream `pqPad`, pq.go:113-127): ISO/IEC 7816-4 (`0x80` + zeros) to the next
/// 64-byte multiple, with a floor. Same delimiter discipline as [`pad_query`]/[`unpad_response`] —
/// only the floor differs: 64 for a fresh (ciphertext-carrying) query, where the 1120-byte KEM
/// ciphertext already dominates the frame length ([`PQ_FRESH_PAD_FLOOR`]).
fn pq_pad(packet: &[u8], floor: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + PAD_BLOCK);
    out.extend_from_slice(packet);
    out.push(0x80);
    let mut target = out.len().div_ceil(PAD_BLOCK) * PAD_BLOCK;
    if target < floor {
        target = floor;
    }
    out.resize(target, 0x00);
    out
}

/// ★ Strip the PQ response control block (upstream `pqStripControl`, pq.go:263-282): the decrypted
/// plaintext is `<control-len(2 BE)><control><padded body>`. The strip is MANDATORY — treating the
/// prefix as body would corrupt the DNS message — but the control CONTENT (a "PQDR" resumption
/// ticket, pq.go:284-309) is deliberately IGNORED: Tortä never sends resumed queries, because a
/// reused ticket links every query it resumes to one client at the resolver — the same linkability
/// leak the per-query ephemeral key (classic path) and per-query encapsulation (PQ path) exist to
/// close. Privacy > the ~1 KiB/query resume saving. A malformed control block (overflowing length)
/// is `None` → the reply is rejected, never mis-sliced.
///
/// D38 — in-place: the plaintext is already an OWNED `Vec` from `aead_open`, so the strip DRAINS the
/// prefix instead of copying the body.
fn pq_strip_control(mut plaintext: Vec<u8>) -> Option<Vec<u8>> {
    if plaintext.len() < 2 {
        return None;
    }
    let control_len = u16::from_be_bytes([plaintext[0], plaintext[1]]) as usize;
    if 2 + control_len > plaintext.len() {
        return None;
    }
    // VALIDATE the block's magic before stripping it. A NON-EMPTY control block begins with
    // `PQCONTROL_MAGIC` ("PQDR", pq.go:29-33); an EMPTY one (`control_len == 0`) carries no magic
    // and is the ordinary no-resumption case.
    //
    // This is a PROTOCOL-MISMATCH detector, not a security gate — the plaintext is already
    // AEAD-authenticated, so a wrong magic cannot be forged by a third party; it means the resolver
    // is speaking a control-block format we do not know. Rejecting is the safe direction and the
    // established one in this very function, which already refuses a reply whose `RESOLVER_MAGIC`
    // does not match. Silently draining `control_len` bytes of an unrecognised format would hand
    // the unpadder a body we have no reason to believe starts where we think it does.
    //
    // The ticket, when the magic IS ours, is still dropped unread — per-query unlinkability beats
    // resume bandwidth (see this function's doc).
    if control_len > 0 {
        if control_len < PQ_CONTROL_MAGIC.len() {
            return None; // too short to carry the magic it must begin with
        }
        if plaintext[2..2 + PQ_CONTROL_MAGIC.len()] != PQ_CONTROL_MAGIC {
            return None; // an unrecognised control-block format
        }
    }
    plaintext.drain(..2 + control_len);
    Some(plaintext)
}

/// ★ Decrypt + authenticate a PQ resolver reply. The wire layout is IDENTICAL to a classic reply
/// (resolver magic + 24-byte nonce with the client-half echo + NaCl XChaCha20 secretbox — upstream
/// `Decrypt` routes XWingPQ through the same `xsecretbox.Open`, crypto.go:233-234); the differences
/// are the HKDF-derived key and the control-block prefix inside the plaintext (crypto.go:247-252:
/// strip control FIRST, then unpad).
fn pq_decrypt_response(
    shared_key: &[u8; 32],
    client_half: &[u8; HALF_NONCE_LEN],
    reply: &[u8],
) -> Result<Vec<u8>, TransportError> {
    if reply.len() < 8 + FULL_NONCE_LEN + AEAD_TAG_LEN {
        return Err(TransportError::BadResponse("PQ reply too short".into()));
    }
    if reply[0..8] != RESOLVER_MAGIC {
        return Err(TransportError::BadResponse("bad resolver magic".into()));
    }
    if reply[8..8 + HALF_NONCE_LEN] != client_half[..] {
        return Err(TransportError::BadResponse(
            "client nonce not echoed".into(),
        ));
    }
    let mut full_nonce = [0u8; FULL_NONCE_LEN];
    full_nonce.copy_from_slice(&reply[8..8 + FULL_NONCE_LEN]);
    let ciphertext = &reply[8 + FULL_NONCE_LEN..];

    let plaintext = aead_open(ES_XCHACHA, shared_key, &full_nonce, ciphertext)?;
    let padded = pq_strip_control(plaintext)
        .ok_or_else(|| TransportError::BadResponse("PQ control block malformed".into()))?;
    unpad_response(padded).ok_or_else(|| TransportError::BadResponse("padding malformed".into()))
}

/// HSalsa20(key, input) — the NaCl `crypto_core_hsalsa20` used by `crypto_box_curve25519xsalsa20`. 32
/// bytes of output (state words 0,5,10,15,6,7,8,9, little-endian). Constants are the Salsa20 "expand
/// 32-byte k" sigma. Pure, allocation-free; mirrors `salsa20::hsalsa::<U10>` (which is a TRANSITIVE
/// dep we cannot import directly here without a Cargo.toml change), so we implement the 10 double-round
/// core inline.
fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let le = |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]);

    let mut x = [0u32; 16];
    x[0] = SIGMA[0];
    x[1] = le(&key[0..4]);
    x[2] = le(&key[4..8]);
    x[3] = le(&key[8..12]);
    x[4] = le(&key[12..16]);
    x[5] = SIGMA[1];
    x[6] = le(&input[0..4]);
    x[7] = le(&input[4..8]);
    x[8] = le(&input[8..12]);
    x[9] = le(&input[12..16]);
    x[10] = SIGMA[2];
    x[11] = le(&key[16..20]);
    x[12] = le(&key[20..24]);
    x[13] = le(&key[24..28]);
    x[14] = le(&key[28..32]);
    x[15] = SIGMA[3];

    for _ in 0..10 {
        // column rounds
        salsa_quarter(&mut x, 0, 4, 8, 12);
        salsa_quarter(&mut x, 5, 9, 13, 1);
        salsa_quarter(&mut x, 10, 14, 2, 6);
        salsa_quarter(&mut x, 15, 3, 7, 11);
        // diagonal rounds
        salsa_quarter(&mut x, 0, 1, 2, 3);
        salsa_quarter(&mut x, 5, 6, 7, 4);
        salsa_quarter(&mut x, 10, 11, 8, 9);
        salsa_quarter(&mut x, 15, 12, 13, 14);
    }

    let mut out = [0u8; 32];
    for (j, &idx) in [0usize, 5, 10, 15, 6, 7, 8, 9].iter().enumerate() {
        out[j * 4..j * 4 + 4].copy_from_slice(&x[idx].to_le_bytes());
    }
    out
}

/// One Salsa20 quarter-round, index-addressed for the HSalsa core above. Matches the canonical
/// `quarter_round(a,b,c,d)` (updates b,c,d,a in turn) used by RustCrypto `salsa20` and DJB's spec.
#[inline(always)]
fn salsa_quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// HChaCha20(key, input) — the `crypto_core_hchacha20` used by `crypto_box_curve25519xchacha20`. 32
/// bytes of output (state words 0..4 ++ 12..16, little-endian). Constants are the ChaCha20 sigma. Pure;
/// mirrors `chacha20::hchacha::<U10>` (a TRANSITIVE dep), implemented inline to avoid a Cargo.toml dep.
fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let le = |s: &[u8]| u32::from_le_bytes([s[0], s[1], s[2], s[3]]);

    let mut x = [0u32; 16];
    x[0] = SIGMA[0];
    x[1] = SIGMA[1];
    x[2] = SIGMA[2];
    x[3] = SIGMA[3];
    for i in 0..8 {
        x[4 + i] = le(&key[i * 4..i * 4 + 4]);
    }
    for i in 0..4 {
        x[12 + i] = le(&input[i * 4..i * 4 + 4]);
    }

    for _ in 0..10 {
        chacha_quarter(&mut x, 0, 4, 8, 12);
        chacha_quarter(&mut x, 1, 5, 9, 13);
        chacha_quarter(&mut x, 2, 6, 10, 14);
        chacha_quarter(&mut x, 3, 7, 11, 15);
        chacha_quarter(&mut x, 0, 5, 10, 15);
        chacha_quarter(&mut x, 1, 6, 11, 12);
        chacha_quarter(&mut x, 2, 7, 8, 13);
        chacha_quarter(&mut x, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    for (j, &idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[j * 4..j * 4 + 4].copy_from_slice(&x[idx].to_le_bytes());
    }
    out
}

/// One ChaCha20 quarter-round, index-addressed for the HChaCha core above.
#[inline(always)]
fn chacha_quarter(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

// ---------------------------------------------------------------------------------------------------
// Stamp decoding — resolver (0x01) + the relay (0x81) scaffold.
// ---------------------------------------------------------------------------------------------------

/// Decode a DNSCrypt `sdns://` resolver stamp into the pieces the datapath needs, or a
/// [`TransportError::Connect`] if it is not a well-formed DNSCrypt stamp. Self-contained because the
/// `dnsstamps` crate is encode-only (see `Cargo.toml`).
///
/// Wire layout after the `sdns://` prefix is base64url(no-pad) of:
/// ```text
///   u8   protocol id            (0x01 = DNSCrypt; anything else ⇒ rejected here)
///   u64  props (LE, flags)      (DNSSEC/NoLogs/NoFilters — not needed by the datapath, skipped)
///   LP   addr   (1-byte len)    resolver "ip:port"; a leading ':' means "default ip, this port"
///   LP   pk     (1-byte len)    32-byte provider Ed25519 public key
///   LP   provider_name          e.g. "2.dnscrypt-cert.example.com"
/// ```
/// `LP` = a single length byte followed by that many bytes. Every read is bounds-checked: a truncated
/// or oversized field is a rejection, never a panic or OOB read.
fn parse_dnscrypt_stamp(stamp: &str) -> Result<Stamp, TransportError> {
    let b64 = stamp
        .strip_prefix(SDNS_PREFIX)
        .ok_or_else(|| TransportError::Connect("stamp is not sdns://".into()))?;
    let bytes = base64url_decode(b64)
        .ok_or_else(|| TransportError::Connect("stamp base64 invalid".into()))?;

    // protocol id + the 8-byte props word.
    let proto = *bytes
        .first()
        .ok_or_else(|| TransportError::Connect("stamp empty".into()))?;
    if proto != STAMP_PROTO_DNSCRYPT {
        // A DoH (0x02) / DoT / relay (0x81) / etc. stamp is not a DNSCrypt resolver stamp.
        return Err(TransportError::Connect(
            "stamp is not DNSCrypt (proto != 0x01)".into(),
        ));
    }
    // 1 (proto) + 8 (props u64) must be present before the first length-prefixed field.
    let mut pos = 1usize + 8;
    if pos > bytes.len() {
        return Err(TransportError::Connect("stamp truncated (props)".into()));
    }

    // LP addr — the resolver "ip:port" string.
    let addr_str = read_lp_str(&bytes, &mut pos)
        .ok_or_else(|| TransportError::Connect("stamp truncated (addr)".into()))?;
    let addr = parse_resolver_addr(&addr_str)
        .ok_or_else(|| TransportError::Connect("stamp addr not ip:port".into()))?;

    // LP pk — exactly 32 bytes of Ed25519 provider public key.
    let pk_slice = read_lp(&bytes, &mut pos)
        .ok_or_else(|| TransportError::Connect("stamp truncated (pk)".into()))?;
    if pk_slice.len() != PROVIDER_PK_LEN {
        return Err(TransportError::Connect("stamp pk not 32 bytes".into()));
    }
    let mut provider_pk = [0u8; PROVIDER_PK_LEN];
    provider_pk.copy_from_slice(pk_slice);

    // LP provider_name — e.g. "2.dnscrypt-cert.example.com".
    let provider_name = read_lp_str(&bytes, &mut pos)
        .ok_or_else(|| TransportError::Connect("stamp truncated (provider name)".into()))?;
    if provider_name.is_empty() {
        return Err(TransportError::Connect("stamp empty provider name".into()));
    }

    Ok(Stamp {
        addr,
        provider_name,
        provider_pk,
    })
}

/// Parse an anonymized-DNSCrypt **relay** stamp (`0x81`) — Slice 2 / T23, NOW WIRED. After the
/// protocol byte it carries a single `LP addr` (the relay `ip:port`); we decode + return it. The relay
/// hop itself is implemented in [`wrap_for_relay`] / [`relayed_udp_then_tcp`], invoked from
/// [`DnsCrypt::encrypted_exchange`] and [`DnsCrypt::ensure_cert`] when a relay chain is attached.
/// `None` if not a relay stamp / malformed.
fn parse_relay_stamp(stamp: &str) -> Option<RelayStamp> {
    let b64 = stamp.strip_prefix(SDNS_PREFIX)?;
    let bytes = base64url_decode(b64)?;
    if *bytes.first()? != STAMP_PROTO_RELAY {
        return None;
    }
    // Relay stamp: proto(1) then LP addr (no props word). Be lenient and just read the first LP after
    // the proto byte as the relay address.
    let mut pos = 1usize;
    let addr_str = read_lp_str(&bytes, &mut pos)?;
    let addr = parse_resolver_addr(&addr_str)?;
    Some(RelayStamp { addr })
}

/// GENESIS relay port: extract the SocketAddr from ANY sdns:// stamp (relay 0x81 or DNSCrypt 0x01).
/// Used by `configure` when the upstream spec carries `"relays":["sdns://..."]`. For relay stamps,
/// delegates to `parse_relay_stamp`. For DNSCrypt stamps, re-parses with the 0x01 layout.
pub(crate) fn parse_stamp_addr(stamp: &str) -> Option<std::net::SocketAddr> {
    // Try relay stamp first (0x81).
    if let Some(r) = parse_relay_stamp(stamp) {
        return Some(r.addr);
    }
    // Fall back: try DNSCrypt stamp (0x01) — extract just the addr.
    let b64 = stamp.strip_prefix(SDNS_PREFIX)?;
    let bytes = base64url_decode(b64)?;
    if bytes.first()? != &STAMP_PROTO_DNSCRYPT {
        return None;
    }
    let mut pos = 1usize + 8; // proto(1) + props(8) for DNSCrypt stamps
    let addr_str = read_lp_str(&bytes, &mut pos)?;
    parse_resolver_addr(&addr_str)
}

/// Decode the ADDRESS FAMILY a stamp is reachable over, host-side, as `(ipv4_ok, ipv6_ok)` — the
/// DATA that lets the manual server picker (and, mirrored in Kotlin, the rotation auto-pick) gate the
/// list by the `ipv4_servers` / `ipv6_servers` toggles (Task #8 Slice B). A V4-literal stamp →
/// `(true,false)`; a V6-literal → `(false,true)`; a HOSTNAME-addressed or empty-addr or undecodable
/// stamp → `(true,true)` = **Unknown**, which is NEVER family-hidden — a manual picker must not hide a
/// pickable server on ambiguous family (the fail-open safety rule; e.g. an ODoH target 0x05 is
/// hostname-addressed by design and rides either family through its relay). Reuses the same byte
/// helpers as [`parse_stamp_addr`] / [`stamp_props`]; never panics, never allocates beyond the decode.
///
/// The `addr` length-prefixed field sits right after the props word on every resolver stamp
/// (0x01 DNSCrypt / 0x02 DoH / 0x03 DoT / 0x05 ODoH-target / 0x85 ODoH-relay carry the 8-byte props),
/// but a bare relay stamp (0x81) has NO props word — its addr LP is the very next field.
pub(crate) fn stamp_addr_family(stamp: &str) -> (bool, bool) {
    let b64 = match stamp.trim().strip_prefix(SDNS_PREFIX) {
        Some(b) => b,
        None => return (true, true),
    };
    let bytes = match base64url_decode(b64) {
        Some(b) => b,
        None => return (true, true),
    };
    let proto = match bytes.first().copied() {
        Some(p) => p,
        None => return (true, true),
    };
    let mut pos = if proto == STAMP_PROTO_RELAY { 1 } else { 1 + 8 };
    match read_lp_str(&bytes, &mut pos) {
        Some(addr) => family_of_addr(&addr),
        None => (true, true),
    }
}

/// Classify a stamp `addr` string into `(ipv4_ok, ipv6_ok)`. An IP literal (with or without a port,
/// or a bracketed `[v6]`) resolves to exactly one family; anything else — empty, port-only, or a
/// hostname (ODoH targets, hostname-addressed DoH) — is **Unknown** `(true,true)` and rides both.
fn family_of_addr(addr: &str) -> (bool, bool) {
    let a = addr.trim();
    if a.is_empty() || a.starts_with(':') {
        return (true, true);
    }
    if let Ok(sa) = a.parse::<SocketAddr>() {
        return if sa.is_ipv6() { (false, true) } else { (true, false) };
    }
    if let Ok(ip) = a.parse::<std::net::IpAddr>() {
        return if ip.is_ipv6() { (false, true) } else { (true, false) };
    }
    if let Some(inner) = a.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if inner.parse::<std::net::Ipv6Addr>().is_ok() {
            return (false, true);
        }
    }
    (true, true)
}

/// Decode an ODoH **target** stamp (`0x05`) into `(hostname, path)` — the pieces the oblivious lane's
/// [`super::odoh::OdohTransport`] needs to build its `https://host/path` target URL. The target is
/// hostname-addressed by design (no IP, no cert hashes — its TLS cert is validated the ordinary way,
/// and its IP is never revealed to the client because the relay dials it). Wire layout after `sdns://`:
/// ```text
///   u8   0x05
///   u64  props (LE flags — DNSSEC/NoLog/NoFilter; not needed here, skipped)
///   LP   hostname   (e.g. "odoh.cloudflare-dns.com")
///   LP   path       (e.g. "/dns-query")
/// ```
/// `None` if not a `0x05` stamp, malformed, truncated, or the hostname is empty. Never panics.
#[cfg(feature = "odoh")]
pub(crate) fn parse_odoh_target_stamp(stamp: &str) -> Option<(String, String)> {
    let b64 = stamp.trim().strip_prefix(SDNS_PREFIX)?;
    let bytes = base64url_decode(b64)?;
    if *bytes.first()? != 0x05 {
        return None;
    }
    let mut pos = 1usize + 8; // proto + props
    if pos > bytes.len() {
        return None;
    }
    let host = read_lp_str(&bytes, &mut pos)?;
    let path = read_lp_str(&bytes, &mut pos)?;
    if host.is_empty() {
        return None;
    }
    Some((host, path))
}

/// Decode an ODoH **relay** stamp (`0x85`) into `(hostname, path)` — the oblivious proxy the query is
/// sent THROUGH so the target never learns the client IP (RFC 9230). Wire layout after `sdns://` (the
/// same shape as a DoH stamp, per the DNS Stamps spec):
/// ```text
///   u8   0x85
///   u64  props (LE flags — skipped)
///   LP   addr    (bootstrap "ip:port"; MAY be empty — we reach the relay by hostname)
///   VLP  hashes  (cert-pin SHA-256 set; skipped — channel trust is the ring-pinned root store)
///   LP   hostname (e.g. "odoh1.surfdomeinen.nl")
///   LP   path     (e.g. "/proxy")
/// ```
/// `None` if not a `0x85` stamp / malformed / truncated / empty hostname. Never panics.
#[cfg(feature = "odoh")]
pub(crate) fn parse_odoh_relay_stamp(stamp: &str) -> Option<(String, String)> {
    let b64 = stamp.trim().strip_prefix(SDNS_PREFIX)?;
    let bytes = base64url_decode(b64)?;
    if *bytes.first()? != 0x85 {
        return None;
    }
    let mut pos = 1usize + 8; // proto + props
    let _addr = read_lp(&bytes, &mut pos)?; // bootstrap addr — may be empty; unused (dial by hostname)
    skip_vlp(&bytes, &mut pos)?; // hashes vector — skip past it
    let host = read_lp_str(&bytes, &mut pos)?;
    let path = read_lp_str(&bytes, &mut pos)?;
    if host.is_empty() {
        return None;
    }
    Some((host, path))
}

/// Skip a `VLP` (vector-length-prefixed) field: a run of `LP` values where the high bit (`0x80`) of
/// each length byte signals "another value follows"; the last has that bit clear. Used to step over
/// the cert-hash set in a `0x85` ODoH-relay (and `0x02` DoH) stamp. Advances `*pos` past the whole
/// vector; `None` on truncation. Never panics.
#[cfg(feature = "odoh")]
fn skip_vlp(bytes: &[u8], pos: &mut usize) -> Option<()> {
    loop {
        let l = *bytes.get(*pos)?;
        let len = (l & 0x7f) as usize;
        let start = *pos + 1;
        let end = start.checked_add(len)?;
        if end > bytes.len() {
            return None;
        }
        *pos = end;
        if l & 0x80 == 0 {
            break;
        }
    }
    Some(())
}

/// Read a single length-prefixed field (`u8` length, then that many bytes) starting at `*pos`, and
/// advance `*pos` past it. Returns the field's bytes, or `None` if it runs off the end. Never panics.
fn read_lp<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = *bytes.get(*pos)? as usize;
    let start = *pos + 1;
    let end = start.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    *pos = end;
    Some(&bytes[start..end])
}

/// Read a length-prefixed field as a UTF-8 `String`. `None` if it runs off the end or isn't UTF-8.
fn read_lp_str(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let raw = read_lp(bytes, pos)?;
    std::str::from_utf8(raw).ok().map(|s| s.to_string())
}

/// Parse a DNSCrypt stamp `addr` field into a `SocketAddr`. A bare `host` (no `:port`) or a leading
/// `:port` defaults to the DNSCrypt port 443; an IPv6 literal must be `[..]:port` bracketed. Returns
/// `None` for anything that is not an IP-literal address (DNS stamps carry IPs, never hostnames).
fn parse_resolver_addr(addr: &str) -> Option<SocketAddr> {
    const DEFAULT_PORT: u16 = 443;
    // Leading ':' (port-only, "default ip") has no IP to dial — reject in the skeleton; the coder may
    // later substitute a provider default. A bare/empty addr is likewise not dialable here.
    if addr.is_empty() || addr.starts_with(':') {
        return None;
    }
    // Already a full SocketAddr ("1.2.3.4:443" or "[2001:db8::1]:443").
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa);
    }
    // A bare IP literal with no port → apply the DNSCrypt default port.
    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, DEFAULT_PORT));
    }
    None
}

/// Classify an `sdns://` stamp by its protocol byte for the manual picker: `"dnscrypt"` (0x01),
/// `"doh"` (0x02), `"doq"` (0x04), `"odoh"` (the 0x05 ODoH target), `"relay"` (the 0x81
/// anonymized-DNSCrypt relay), `"odoh-relay"` (0x85), or `"other"` (DoT 0x03 / malformed). The
/// server picker filters on `dnscrypt`/`doh`/`doq`/`odoh`; the relay picker takes the
/// `relay`/`odoh-relay` entries. Never panics.
pub(crate) fn stamp_proto_label(stamp: &str) -> &'static str {
    let b64 = match stamp.trim().strip_prefix(SDNS_PREFIX) {
        Some(b) => b,
        None => return "other",
    };
    match base64url_decode(b64).and_then(|b| b.first().copied()) {
        Some(STAMP_PROTO_DNSCRYPT) => "dnscrypt", // 0x01
        Some(0x02) => "doh",
        Some(0x04) => "doq",
        Some(0x05) => "odoh", // ODoH target (hostname-addressed; props word present per the spec)
        Some(STAMP_PROTO_RELAY) => "relay", // 0x81 anonymized-DNSCrypt relay
        Some(0x85) => "odoh-relay",
        _ => "other",
    }
}

/// Extract the `(dnssec, no_log, no_filter)` property flags from an `sdns://` stamp's props word (the
/// LOW byte of the little-endian `u64` right after the proto byte: bit0 DNSSEC · bit1 no-log · bit2
/// no-filter — the DNS Stamps spec, same bits [`crate::resolver::RotationPoolSource`] reads). The
/// props word is present on the resolver stamps (0x01 DNSCrypt / 0x02 DoH / 0x03 DoT / 0x05 ODoH),
/// but NOT on a relay stamp (0x81) → `(false,false,false)`. Malformed → all false. Never panics.
/// The DATA that makes the manual picker LIVE-WIRED — the host filters rows by the armed require_*.
pub(crate) fn stamp_props(stamp: &str) -> (bool, bool, bool) {
    let b64 = match stamp.trim().strip_prefix(SDNS_PREFIX) {
        Some(b) => b,
        None => return (false, false, false),
    };
    match base64url_decode(b64) {
        Some(bytes) if bytes.len() >= 2 && bytes[0] != STAMP_PROTO_RELAY => {
            let p = bytes[1];
            ((p & 1) == 1, ((p >> 1) & 1) == 1, ((p >> 2) & 1) == 1)
        }
        _ => (false, false, false),
    }
}

/// Minimal RFC 4648 base64url (`-`/`_`, no padding) decoder — DNS Stamps are base64url, unpadded. We
/// roll our own so 2d needs no base64 dep on top of the crypto crates. Returns `None` on any invalid
/// character or a dangling 1-char tail (an impossible base64 length). Never panics.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('='); // tolerate accidental padding
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        let v = val(c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    // A valid base64 stream leaves < 6 leftover bits, all zero (a lone 6-bit group is malformed).
    if bits >= 6 || (buf & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid DNSCrypt stamp's binary body and base64url(no-pad)-encode it into an `sdns://`
    /// string, so the parser can be exercised without a network or a real provider.
    pub(super) fn make_stamp(proto: u8, addr: &str, pk: &[u8], provider: &str) -> String {
        let mut body = Vec::new();
        body.push(proto);
        body.extend_from_slice(&0u64.to_le_bytes()); // props (flags) — unused by the datapath
        body.push(addr.len() as u8);
        body.extend_from_slice(addr.as_bytes());
        body.push(pk.len() as u8);
        body.extend_from_slice(pk);
        body.push(provider.len() as u8);
        body.extend_from_slice(provider.as_bytes());
        format!("{SDNS_PREFIX}{}", base64url_encode(&body))
    }

    /// Test-only encoder mirroring `base64url_decode` (RFC 4648 url alphabet, no padding).
    fn base64url_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut buf = 0u32;
        let mut bits = 0u32;
        for &b in data {
            buf = (buf << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buf >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buf << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }

    /// Build a DNSCrypt cert and Ed25519-SIGN its signed region with `signing` — a host-only forge so
    /// the T14 verification path can be exercised without a real provider. `es_version`, the validity
    /// window, the resolver pk + client-magic are all caller-controlled.
    fn make_signed_cert(
        signing: &ed25519_dalek::SigningKey,
        es_version: u16,
        resolver_pk: &[u8; 32],
        client_magic: &[u8; 8],
        ts_start: u32,
        ts_end: u32,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        // Build the signed region first: resolver_pk(32) || client_magic(8) || serial(4) || ts_start(4)
        //   || ts_end(4)  (no extensions).
        let mut signed = Vec::new();
        signed.extend_from_slice(resolver_pk);
        signed.extend_from_slice(client_magic);
        signed.extend_from_slice(&1u32.to_be_bytes()); // serial
        signed.extend_from_slice(&ts_start.to_be_bytes());
        signed.extend_from_slice(&ts_end.to_be_bytes());

        let sig = signing.sign(&signed);

        let mut cert = Vec::new();
        cert.extend_from_slice(&CERT_MAGIC); // "DNSC"
        cert.extend_from_slice(&es_version.to_be_bytes());
        cert.extend_from_slice(&0u16.to_be_bytes()); // protocol minor
        cert.extend_from_slice(&sig.to_bytes()); // 64-byte signature
        cert.extend_from_slice(&signed); // the signed region at offset 72
        cert
    }

    /// Like `make_signed_cert`, but with a caller-controlled SIGNED `serial` (bytes[112..116]) — for
    /// the FIX 3 freshness tests (highest serial among equal-es certs wins).
    fn make_signed_cert_serial(
        signing: &ed25519_dalek::SigningKey,
        es_version: u16,
        resolver_pk: &[u8; 32],
        client_magic: &[u8; 8],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut signed = Vec::new();
        signed.extend_from_slice(resolver_pk);
        signed.extend_from_slice(client_magic);
        signed.extend_from_slice(&serial.to_be_bytes()); // SIGNED serial
        signed.extend_from_slice(&ts_start.to_be_bytes());
        signed.extend_from_slice(&ts_end.to_be_bytes());

        let sig = signing.sign(&signed);

        let mut cert = Vec::new();
        cert.extend_from_slice(&CERT_MAGIC);
        cert.extend_from_slice(&es_version.to_be_bytes());
        cert.extend_from_slice(&0u16.to_be_bytes());
        cert.extend_from_slice(&sig.to_bytes());
        cert.extend_from_slice(&signed);
        cert
    }

    /// Wrap one cert blob as the RDATA of a single-TXT DNS answer to a TXT query for `provider`, so
    /// `parse_cert_txts` can extract it. (TXT RDATA is one `<len><bytes>` character-string; a DNSCrypt
    /// cert is < 256 bytes so it fits one string.)
    fn make_txt_response(provider: &str, cert: &[u8]) -> Vec<u8> {
        let q = build_txt_query(provider);
        let (_, qend) = (
            (),
            // recompute the question end: header(12) + name + qtype(2) + qclass(2)
            {
                let mut pos = 12usize;
                pos = skip_name(&q, pos).unwrap();
                pos + 4
            },
        );
        let mut resp = q[..qend].to_vec();
        resp[2] |= 0x80; // QR = 1
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
                                                         // Answer: owner = compression pointer to the question name at offset 12.
        resp.push(0xC0);
        resp.push(0x0C);
        resp.extend_from_slice(&16u16.to_be_bytes()); // TYPE = TXT
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        let rdata_len = 1 + cert.len(); // one character-string: <len><cert bytes>
        resp.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        resp.push(cert.len() as u8);
        resp.extend_from_slice(cert);
        resp
    }

    // ---- stamp parse (rejects non-dnscrypt) ----

    #[test]
    fn parses_a_well_formed_dnscrypt_stamp() {
        let pk = [7u8; 32];
        let stamp = make_stamp(
            STAMP_PROTO_DNSCRYPT,
            "1.2.3.4:443",
            &pk,
            "2.dnscrypt-cert.example.com",
        );
        let t = DnsCrypt::new("dnscrypt:test", &stamp).expect("a valid DNSCrypt stamp parses");
        assert_eq!(t.id(), "dnscrypt:test");
        assert_eq!(t.addr, "1.2.3.4:443".parse::<SocketAddr>().unwrap());
        assert_eq!(t.provider_name, "2.dnscrypt-cert.example.com");
        assert_eq!(t.provider_pk, pk);
    }

    #[test]
    fn bare_ip_addr_gets_default_dnscrypt_port() {
        let stamp = make_stamp(STAMP_PROTO_DNSCRYPT, "9.9.9.9", &[1u8; 32], "p.example");
        let t = DnsCrypt::new("x", &stamp).expect("bare ip stamp parses");
        assert_eq!(t.addr, "9.9.9.9:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_non_sdns_scheme() {
        assert!(matches!(
            DnsCrypt::new("x", "https://not-a-stamp.example/"),
            Err(TransportError::Connect(_))
        ));
    }

    #[test]
    fn rejects_non_dnscrypt_protocol() {
        // proto 0x02 = DoH stamp — a real stamp, but NOT a DNSCrypt resolver stamp.
        let stamp = make_stamp(0x02, "1.2.3.4:443", &[0u8; 32], "doh.example");
        match DnsCrypt::new("x", &stamp) {
            Err(TransportError::Connect(m)) => assert!(m.contains("DNSCrypt"), "msg: {m}"),
            Err(other) => panic!("expected a Connect rejection, got {other:?}"),
            Ok(_) => panic!("a non-DNSCrypt (proto 0x02) stamp must be rejected"),
        }
    }

    #[test]
    fn rejects_pk_of_wrong_length() {
        let stamp = make_stamp(STAMP_PROTO_DNSCRYPT, "1.2.3.4:443", &[0u8; 31], "p.example");
        assert!(matches!(
            DnsCrypt::new("x", &stamp),
            Err(TransportError::Connect(_))
        ));
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(matches!(
            DnsCrypt::new("x", "sdns://!!!not base64!!!"),
            Err(TransportError::Connect(_))
        ));
    }

    #[test]
    fn rejects_truncated_stamp() {
        let truncated = format!("{SDNS_PREFIX}{}", base64url_encode(&[STAMP_PROTO_DNSCRYPT]));
        assert!(matches!(
            DnsCrypt::new("x", &truncated),
            Err(TransportError::Connect(_))
        ));
    }

    // ---- stamp ADDRESS-FAMILY decode (Task #8 Slice B: the manual-picker ipv4/ipv6 gate) ----

    /// Build a bare relay stamp (0x81): proto byte then a single LP addr, NO props word — the layout
    /// `stamp_addr_family` must position past differently from a resolver stamp.
    pub(super) fn make_relay_stamp(addr: &str) -> String {
        let mut body = Vec::new();
        body.push(STAMP_PROTO_RELAY);
        body.push(addr.len() as u8);
        body.extend_from_slice(addr.as_bytes());
        format!("{SDNS_PREFIX}{}", base64url_encode(&body))
    }

    #[test]
    fn family_of_v4_literals_is_ipv4_only() {
        // Bare V4, ported V4, DoH-ported V4 — each resolves to exactly the IPv4 family.
        for stamp in [
            make_stamp(STAMP_PROTO_DNSCRYPT, "9.9.9.9", &[1u8; 32], "p.example"),
            make_stamp(STAMP_PROTO_DNSCRYPT, "1.2.3.4:443", &[1u8; 32], "p.example"),
            make_stamp(0x02, "8.8.8.8:443", &[0u8; 32], "doh.example"),
            make_relay_stamp("45.32.55.94:443"),
        ] {
            assert_eq!(stamp_addr_family(&stamp), (true, false), "stamp: {stamp}");
        }
    }

    #[test]
    fn family_of_v6_literals_is_ipv6_only() {
        for stamp in [
            make_stamp(
                STAMP_PROTO_DNSCRYPT,
                "[2606:4700:4700::1111]:443",
                &[1u8; 32],
                "p.example",
            ),
            make_stamp(0x02, "[2001:4860:4860::8888]:443", &[0u8; 32], "doh.example"),
            make_relay_stamp("[2001:19f0::1]:443"),
        ] {
            assert_eq!(stamp_addr_family(&stamp), (false, true), "stamp: {stamp}");
        }
    }

    #[test]
    fn family_of_hostname_or_empty_addr_is_unknown_both() {
        // A hostname-addressed DoH (empty addr LP) and an ODoH target are reachable over EITHER family
        // through their front/relay — Unknown → (true,true), never family-hidden by the picker.
        let hostless_doh = make_stamp(0x02, "", &[0u8; 32], "doh.example");
        assert_eq!(stamp_addr_family(&hostless_doh), (true, true));
        let port_only = make_stamp(STAMP_PROTO_DNSCRYPT, ":443", &[1u8; 32], "p.example");
        assert_eq!(stamp_addr_family(&port_only), (true, true));
    }

    #[test]
    fn family_of_garbage_fails_open_to_unknown() {
        // Non-sdns, bad base64, truncated — all fail OPEN to Unknown so a decode fault never silently
        // hides an otherwise-pickable server.
        assert_eq!(stamp_addr_family("https://not-a-stamp.example/"), (true, true));
        assert_eq!(stamp_addr_family("sdns://!!!not base64!!!"), (true, true));
        let truncated = format!("{SDNS_PREFIX}{}", base64url_encode(&[STAMP_PROTO_DNSCRYPT]));
        assert_eq!(stamp_addr_family(&truncated), (true, true));
    }

    #[test]
    fn relay_stamp_parses_and_is_not_a_resolver_transport() {
        // 0x81 relay stamp: proto + LP addr. parse_relay_stamp returns the relay addr, which the
        // relayed datapath (wrap_for_relay / relayed_udp_then_tcp) dials when a chain is attached.
        let mut body = Vec::new();
        body.push(STAMP_PROTO_RELAY);
        let addr = "5.6.7.8:443";
        body.push(addr.len() as u8);
        body.extend_from_slice(addr.as_bytes());
        let stamp = format!("{SDNS_PREFIX}{}", base64url_encode(&body));
        let relay = parse_relay_stamp(&stamp).expect("relay stamp parses");
        assert_eq!(relay.addr, "5.6.7.8:443".parse::<SocketAddr>().unwrap());
        // And a relay stamp is NOT accepted as a resolver transport.
        assert!(matches!(
            DnsCrypt::new("x", &stamp),
            Err(TransportError::Connect(_))
        ));
    }

    // ---- Slice 2 (T23): the anonymized-DNSCrypt relay envelope ----
    //
    // The relay hop is the byte-for-byte Rust mirror of the Go `prepareForRelay`
    // (dnscrypt-proxy/proxy.go:589-597): `[0xff×8][0x00 0x00][ip.To16()][port BE][payload]`. These
    // tests pin the envelope format, the IPv4→IPv4-mapped-IPv6 expansion (load-bearing — a relay
    // parses a fixed 16-byte IPv6 field), the multi-hop chain nesting order, and the empty-chain
    // direct path (byte-identical to pre-Slice-2).

    /// The canonical Go `prepareForRelay` envelope, reproduced exactly. A relayed query is the
    /// 10-byte anonymized header + the resolver IP as a 16-byte IPv6 (IPv4-mapped) + the port
    /// big-endian + the original payload.
    #[test]
    fn relay_envelope_matches_go_prepare_for_relay_ipv4() {
        let payload = b"ENCRYPTED-FRAME-BYTES";
        let resolver: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let wrapped = wrap_for_relay(payload, resolver);

        // 10-byte anonymized header (0xff × 8, then 0x00 0x00) — proxy.go:590.
        assert_eq!(
            &wrapped[..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00]
        );
        // IPv4 → IPv4-mapped IPv6 (::ffff:1.2.3.4), 16 bytes — Go's net.IP.To16().
        assert_eq!(
            &wrapped[10..26],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x02,
                0x03, 0x04
            ],
            "IPv4 must be emitted as its 16-byte IPv4-mapped IPv6 form (::ffff:a.b.c.d)"
        );
        // Port 443 big-endian.
        assert_eq!(&wrapped[26..28], &[0x01, 0xBB], "port must be big-endian");
        assert_eq!(&wrapped[28..], payload);
        assert_eq!(wrapped.len(), 10 + 16 + 2 + payload.len());
    }

    /// A native IPv6 resolver address is emitted as-is (16 bytes), not re-mapped.
    #[test]
    fn relay_envelope_emits_native_ipv6_as_is() {
        let payload = b"x";
        let resolver: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let wrapped = wrap_for_relay(payload, resolver);
        assert_eq!(&wrapped[..10], &RELAY_HEADER);
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x0d;
        v6[3] = 0xb8;
        v6[15] = 0x01;
        assert_eq!(&wrapped[10..26], &v6);
        assert_eq!(&wrapped[26..28], &[0x01, 0xBB]);
        assert_eq!(&wrapped[28..], payload);
    }

    /// The empty-chain path: `wrap_for_relay_chain` with NO relays returns the payload UNCHANGED
    /// and the resolver as the dial target — byte-identical to the pre-Slice-2 direct path.
    #[test]
    fn relay_chain_empty_is_byte_identical_to_direct() {
        let payload = b"PLAIN-FRAME";
        let resolver: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let (wire, dial) = wrap_for_relay_chain(payload, resolver, &[]);
        assert_eq!(
            wire, payload,
            "no relay → payload unchanged (no envelope added)"
        );
        assert_eq!(dial, resolver, "no relay → dial the resolver directly");
    }

    /// The common production case (the upstream Go proxy uses ONE relay per query): a one-element
    /// chain collapses to a single envelope addressed to that relay, with the resolver embedded.
    #[test]
    fn relay_chain_single_hop_wraps_once_and_dials_the_relay() {
        let payload = b"ENCRYPTED";
        let resolver: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let relay: SocketAddr = "9.9.9.9:443".parse().unwrap();
        let (wire, dial) = wrap_for_relay_chain(payload, resolver, &[relay]);

        assert_eq!(dial, relay, "dial target is the RELAY, not the resolver");
        let expected = wrap_for_relay(payload, resolver);
        assert_eq!(
            wire, expected,
            "single-hop chain = one envelope around the resolver"
        );
        assert_eq!(
            &wire[10..26],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x01,
                0x01, 0x01
            ],
            "the inner next-hop embedded in the envelope is the RESOLVER (1.1.1.1), not the relay"
        );
    }

    /// The spec's multi-hop nesting: each envelope's embedded next-hop is the relay (or resolver)
    /// that the receiving relay forwards to. The FIRST relay is the dial target (never embedded);
    /// the outermost envelope embeds the SECOND relay, the inner envelope embeds the resolver.
    #[test]
    fn relay_chain_multi_hop_nests_in_reverse_order() {
        let payload = b"INNER";
        let resolver: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let relay_a: SocketAddr = "10.0.0.1:443".parse().unwrap(); // dialed first
        let relay_b: SocketAddr = "10.0.0.2:443".parse().unwrap(); // hop after relay_a
        let (wire, dial) = wrap_for_relay_chain(payload, resolver, &[relay_a, relay_b]);

        assert_eq!(dial, relay_a, "we dial the FIRST relay (never embedded)");

        // Reconstruct by hand: inner envelope → resolver; outer envelope → relay_b (relay_a forwards
        // to relay_b). relay_a is the dial target, so it gets NO envelope of its own.
        let inner = wrap_for_relay(payload, resolver);
        let outer = wrap_for_relay(&inner, relay_b);
        assert_eq!(
            wire, outer,
            "inner → resolver, outer → relay_b (dialed at relay_a)"
        );

        // Peel the outermost envelope to prove the structure: outermost next-hop is relay_b, inside
        // that is an envelope addressed to the resolver.
        assert_eq!(&wire[..10], &RELAY_HEADER, "outermost header");
        assert_eq!(
            &wire[10..26],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x00,
                0x00, 0x02
            ],
            "outermost envelope → relay_b (10.0.0.2)"
        );
        assert_eq!(&wire[26..28], &[0x01, 0xBB], "outermost port BE");
        let inner_envelope = &wire[28..];
        assert_eq!(&inner_envelope[..10], &RELAY_HEADER, "inner header");
        assert_eq!(
            &inner_envelope[10..26],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x01,
                0x01, 0x01
            ],
            "inner envelope → resolver (1.1.1.1)"
        );
    }

    /// `parse_relay_chain` is lenient: a malformed/non-relay stamp in the `via` list is dropped
    /// (matches the Go resolver, which skips a bad relay); empty input → empty chain (direct).
    #[test]
    fn parse_relay_chain_drops_bad_stamps_and_empty_is_direct() {
        assert!(
            DnsCrypt::parse_relay_chain(&[]).is_empty(),
            "empty input → empty chain"
        );

        let mut body = Vec::new();
        body.push(STAMP_PROTO_RELAY);
        let addr = "5.6.7.8:443";
        body.push(addr.len() as u8);
        body.extend_from_slice(addr.as_bytes());
        let good = format!("{SDNS_PREFIX}{}", base64url_encode(&body));

        let bad = make_stamp(STAMP_PROTO_DNSCRYPT, "1.2.3.4:443", &[0u8; 32], "p.example");
        let chain = DnsCrypt::parse_relay_chain(&[&good, &bad, "sdns://!!!garbage!!!"]);
        assert_eq!(chain.len(), 1, "only the valid relay stamp survives");
        assert_eq!(chain[0], "5.6.7.8:443".parse::<SocketAddr>().unwrap());
    }

    /// `set_relays` / `with_relays` attach the chain; empty resets to direct. The addrs are stored
    /// verbatim.
    #[test]
    fn set_relays_and_with_relays_attach_the_chain() {
        let pk = [7u8; 32];
        let stamp = make_stamp(
            STAMP_PROTO_DNSCRYPT,
            "1.2.3.4:443",
            &pk,
            "2.dnscrypt-cert.example.com",
        );
        let relay: SocketAddr = "9.9.9.9:443".parse().unwrap();

        let t = DnsCrypt::with_relays("x", &stamp, vec![relay]).expect("parses");
        assert_eq!(t.relays, vec![relay]);

        let mut t2 = DnsCrypt::new("x", &stamp).expect("parses");
        assert!(t2.relays.is_empty(), "default is direct (no relay)");
        t2.set_relays(vec![relay]);
        assert_eq!(t2.relays, vec![relay]);
        t2.set_relays(Vec::new());
        assert!(t2.relays.is_empty(), "empty chain resets to direct");
    }

    // ---- T14 cert verification ----

    #[test]
    fn rejects_expired_cert() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        // valid window ENDED at t=1000; "now" = 2000 → expired.
        let cert = make_signed_cert(&signing, ES_XCHACHA, &[0x11; 32], b"clientmg", 0, 1000);
        assert!(
            select_best_cert(&[cert], &provider_pk, 2000, true).is_none(),
            "expired cert must be refused"
        );
    }

    #[test]
    fn rejects_not_yet_valid_cert() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        // window starts at t=5000; "now" = 100 → not yet valid.
        let cert = make_signed_cert(&signing, ES_XCHACHA, &[0x22; 32], b"clientmg", 5000, 9000);
        assert!(
            select_best_cert(&[cert], &provider_pk, 100, true).is_none(),
            "not-yet-valid cert refused"
        );
    }

    #[test]
    fn rejects_wrong_ed25519_signature() {
        // Sign with one key, verify against a DIFFERENT provider pk → must be rejected.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let attacker_pk = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
            .verifying_key()
            .to_bytes();
        let cert = make_signed_cert(&signing, ES_XCHACHA, &[0x33; 32], b"clientmg", 0, 9999);
        assert!(
            select_best_cert(&[cert], &attacker_pk, 100, true).is_none(),
            "a cert signed by another key must fail Ed25519 verification"
        );
    }

    #[test]
    fn rejects_tampered_signed_region() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let mut cert = make_signed_cert(&signing, ES_XCHACHA, &[0x44; 32], b"clientmg", 0, 9999);
        // Flip a byte inside the signed region (the resolver pk at offset 72) → signature no longer
        // covers it → rejected (tamper detected, no crash).
        cert[80] ^= 0xFF;
        assert!(select_best_cert(&[cert], &provider_pk, 100, true).is_none());
    }

    #[test]
    fn es_version_selection_picks_the_highest_valid() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let v1 = make_signed_cert(&signing, ES_XSALSA, &[0x01; 32], b"v1magic_", 0, 9999);
        let v2 = make_signed_cert(&signing, ES_XCHACHA, &[0x02; 32], b"v2magic_", 0, 9999);
        // Both valid + in-window; the highest es_version (2 = XChaCha20) must win, regardless of order.
        let best =
            select_best_cert(&[v1.clone(), v2.clone()], &provider_pk, 100, true).expect("a valid cert");
        assert_eq!(best.es_version, ES_XCHACHA);
        assert_eq!(best.resolver_pk, [0x02; 32]);
        let best_rev = select_best_cert(&[v2, v1], &provider_pk, 100, true).expect("a valid cert");
        assert_eq!(
            best_rev.es_version, ES_XCHACHA,
            "never downgrade even if v1 is listed last"
        );
    }

    #[test]
    fn cert_txt_round_trips_through_the_dns_walker() {
        // A signed cert wrapped as a TXT answer must be extracted by parse_cert_txts and then chosen.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let cert = make_signed_cert(&signing, ES_XCHACHA, &[0x55; 32], b"clientmg", 0, 9999);
        let resp = make_txt_response("2.dnscrypt-cert.example.com", &cert);
        let blobs = parse_cert_txts(&resp).expect("a TXT blob");
        assert_eq!(blobs.len(), 1);
        let best = select_best_cert(&blobs, &provider_pk, 100, true).expect("the cert is valid");
        assert_eq!(best.es_version, ES_XCHACHA);
        assert_eq!(best.client_magic, *b"clientmg");
    }

    // ---- FIX 2 — es_version is UNSIGNED: a flip must not silently downgrade the cipher ----

    #[test]
    fn flipped_es_version_does_not_silently_downgrade_cipher() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let resolver_pk = [0x77u8; 32];
        let magic = b"es2magic";

        // The provider's GENUINE es-2 (XChaCha20-Poly1305) cert. Signed region = everything from
        // offset 72. The `es_version` header (bytes[4..6]) is OUTSIDE that signed region.
        let genuine_es2 = make_signed_cert(&signing, ES_XCHACHA, &resolver_pk, magic, 0, 9999);
        // Baseline: the genuine es-2 cert is selected and seals XChaCha20.
        let ok = select_best_cert(&[genuine_es2.clone()], &provider_pk, 100, true)
            .expect("the genuine es-2 cert is valid");
        assert_eq!(
            ok.es_version, ES_XCHACHA,
            "genuine es-2 cert seals XChaCha20"
        );

        // ATTACK: an on-path adversary flips ONLY the UNSIGNED es_version header 2 → 1, coercing the
        // weaker XSalsa20 cipher. Nothing in the Ed25519-signed region changes, so `verify_strict`
        // STILL passes — the classic silent cipher-downgrade vector.
        let mut flipped = genuine_es2.clone();
        flipped[4..6].copy_from_slice(&ES_XSALSA.to_be_bytes());
        // Sanity: the flip changed ONLY the unsigned header (the signed region is byte-identical),
        // so the signature still verifies — this is what makes the downgrade "silent".
        assert_eq!(parse_cert(&flipped).unwrap().es_version, ES_XSALSA);
        assert_eq!(
            &flipped[72..],
            &genuine_es2[72..],
            "signed region untouched by the flip"
        );

        // BEFORE the fix: `select_best_cert` routes the cipher off the unsigned header, returns a
        // cert with es_version == ES_XSALSA → SILENT DOWNGRADE (test FAILS, it expects rejection).
        // AFTER the fix: the cipher is bound to the SIGNED region; an es_version chosen via the
        // flippable header is NOT trusted to downgrade to XSalsa20, so the flipped cert is REJECTED.
        assert!(
            select_best_cert(&[flipped], &provider_pk, 100, true).is_none(),
            "a genuine es-2 cert with its es_version flipped to 1 must be REJECTED, never downgraded"
        );
    }

    // ---- FIX 3 — serial-based freshness: highest serial of equal es_version wins ----

    #[test]
    fn highest_serial_wins_among_equal_es_version_certs() {
        // A hostile resolver lists a RETIRED (low-serial) key to pin clients to it. Among validly
        // signed, in-window certs of EQUAL es_version, the HIGHEST serial (freshest) must be chosen,
        // regardless of the order the resolver returns them.
        //
        // BEFORE the fix `parse_cert` does not read the serial and `select_best_cert` keeps the FIRST
        // equal-es cert it sees, so the chosen resolver_pk depends on resolver-controlled order →
        // this test FAILS (one of the two orderings picks the retired key). AFTER the fix the freshest
        // (serial 9) wins in both orderings.
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();

        let retired =
            make_signed_cert_serial(&signing, ES_XCHACHA, &[0xAA; 32], b"oldmagic", 1, 0, 9999);
        let fresh =
            make_signed_cert_serial(&signing, ES_XCHACHA, &[0xBB; 32], b"newmagic", 9, 0, 9999);

        let pick_a = select_best_cert(&[retired.clone(), fresh.clone()], &provider_pk, 100, true)
            .expect("a valid cert");
        let pick_b = select_best_cert(&[fresh.clone(), retired.clone()], &provider_pk, 100, true)
            .expect("a valid cert");
        assert_eq!(
            pick_a.serial, 9,
            "highest serial wins (retired listed first)"
        );
        assert_eq!(pick_a.resolver_pk, [0xBB; 32]);
        assert_eq!(pick_b.serial, 9, "highest serial wins (fresh listed first)");
        assert_eq!(pick_b.resolver_pk, [0xBB; 32]);
    }

    // ---- FIX 4 — Y2106: validity-window compare must not narrow `now` to u32 ----

    #[test]
    fn validity_window_is_y2106_safe() {
        // FIX 4 — the window compare must treat `now` as u64 end-to-end. The pre-fix inline check did
        // `(now as u32) < ts_start`, which WRAPS once `now` crosses 2^32 (year 2106). This pins the
        // exact case where the narrowing flips the verdict, via the extracted `cert_in_window` helper
        // (the same predicate `select_best_cert` uses), so the bug is observable independent of the
        // u32 on-wire timestamp ceiling.
        //
        // `now` just past 2^32 (a 2106-era clock); window = [5000, 2^33). Genuinely IN-WINDOW (u64):
        //   now(2^32+100) >= 5000  AND  now < 2^33  → true.
        // BUT the narrowing bug computes `(now as u32) = 100`, and `100 < 5000` → it would WRONGLY
        // classify the cert as "not yet valid" and reject it.
        let now_post_2106: u64 = (u32::MAX as u64) + 1 + 100; // 2^32 + 100
        let ts_start: u64 = 5000;
        let ts_end: u64 = 1u64 << 33;
        assert!(
            cert_in_window(now_post_2106, ts_start, ts_end),
            "a post-2106 `now` inside [ts_start, ts_end) must read IN-WINDOW (u64 compare, no u32 wrap)"
        );
        // Cross-check: the narrowing the OLD code did would have said the opposite (the smoking gun).
        let narrowed = (now_post_2106 as u32) as u64; // == 100
        assert!(
            narrowed < ts_start,
            "the OLD `(now as u32)` narrowing wraps to {narrowed} and mis-reads the window"
        );

        // Sanity: normal boundaries still behave. Not-yet-valid, in-window, and expired all correct.
        assert!(
            !cert_in_window(4999, 5000, ts_end),
            "before ts_start = not yet valid"
        );
        assert!(
            cert_in_window(5000, 5000, ts_end),
            "at ts_start = valid (inclusive)"
        );
        assert!(
            !cert_in_window(ts_end, 5000, ts_end),
            "at ts_end = expired (exclusive)"
        );

        // And the full select_best_cert path still accepts a normal in-window cert (no regression).
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let live = make_signed_cert(&signing, ES_XCHACHA, &[0x67; 32], b"livemag_", 10, u32::MAX);
        assert!(
            select_best_cert(&[live], &provider_pk, 1_000_000_000, true).is_some(),
            "an in-window cert at a normal `now` is still accepted"
        );
    }

    // ---- T21 padding round-trip + block alignment ----

    #[test]
    fn pad_unpad_round_trips_and_is_block_aligned() {
        for q in [
            &b""[..],
            &b"\x00"[..],
            &b"hello dnscrypt query bytes"[..],
            &vec![0xABu8; 300][..],
        ] {
            let padded = pad_query(q);
            // block-aligned and at least the minimum.
            assert!(
                padded.len() >= MIN_PADDED,
                "padded {} >= {}",
                padded.len(),
                MIN_PADDED
            );
            assert_eq!(
                padded.len() % PAD_BLOCK,
                0,
                "padded length is a {PAD_BLOCK}-byte multiple"
            );
            // the delimiter is present and round-trips back to the original.
            let back = unpad_response(padded).expect("unpad");
            assert_eq!(back, q, "pad/unpad must round-trip");
        }
    }

    #[test]
    fn unpad_rejects_all_zero_or_missing_delimiter() {
        assert!(unpad_response(vec![0u8; 16]).is_none()); // no 0x80 delimiter
        assert!(unpad_response(Vec::new()).is_none()); // empty
    }

    // ---- AEAD seal/open round-trip + tamper detection (both es-versions) ----

    #[test]
    fn aead_seal_open_round_trips_xchacha() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; FULL_NONCE_LEN];
        let msg = b"the inner padded dns query bytes";
        let sealed = aead_seal(ES_XCHACHA, &key, &nonce, msg).expect("seal");
        let opened = aead_open(ES_XCHACHA, &key, &nonce, &sealed).expect("open");
        assert_eq!(&opened, msg);
    }

    #[test]
    fn aead_seal_open_round_trips_xsalsa() {
        let key = [0x13u8; 32];
        let nonce = [0x37u8; FULL_NONCE_LEN];
        let msg = b"legacy es-version 1 payload";
        let sealed = aead_seal(ES_XSALSA, &key, &nonce, msg).expect("seal");
        let opened = aead_open(ES_XSALSA, &key, &nonce, &sealed).expect("open");
        assert_eq!(&opened, msg);
    }

    #[test]
    fn aead_single_tampered_byte_fails_to_open() {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; FULL_NONCE_LEN];
        let msg = b"authenticate me";
        let mut sealed = aead_seal(ES_XCHACHA, &key, &nonce, msg).expect("seal");
        // Flip one ciphertext byte → Poly1305 tag fails → Err, never a panic.
        sealed[0] ^= 0x01;
        assert!(
            aead_open(ES_XCHACHA, &key, &nonce, &sealed).is_err(),
            "tamper must fail the tag"
        );
        // And a flipped TAG byte (last byte) also fails.
        let mut sealed2 = aead_seal(ES_XSALSA, &key, &nonce, msg).expect("seal");
        let last = sealed2.len() - 1;
        sealed2[last] ^= 0x80;
        assert!(aead_open(ES_XSALSA, &key, &nonce, &sealed2).is_err());
    }

    // ---- FIX 1 — es-v2 AEAD is the NaCl crypto_secretbox MAC VALUE, not the IETF one ----

    /// THE HEADLINE KAT. es-v2 must be the NaCl `crypto_secretbox_xchacha20poly1305` box (Poly1305 over
    /// the CIPHERTEXT ONLY, no RFC-8439 length block), byte-for-byte. The prior fix corrected only the
    /// tag POSITION (tag||ciphertext) but kept the IETF `chacha20poly1305 0.10.1` MAC VALUE, which also
    /// hashes a 16-byte length block (`cipher.rs::authenticate_lengths`) — a DIFFERENT, WRONG tag for
    /// the NaCl construction a real DNSCrypt resolver runs.
    ///
    /// The vector is a LIBSODIUM-reference `crypto_secretbox_xchacha20poly1305` KAT (key, 24-byte nonce,
    /// plaintext → exact `tag||ciphertext`), lifted from RustCrypto `crypto_secretbox 0.1.1`'s own
    /// `tests/lib.rs` (header: "XChaCha20Poly1305 test vectors generated using `test-vector-gen` which
    /// uses a libsodium reference"). It is NOT self-referential — it is an external libsodium answer.
    ///
    /// FAIL-before / PASS-after: the old es-v2 seal (IETF MAC, tag repositioned) does NOT reproduce this
    /// vector and DOES equal the IETF box on the tag bytes; the new NaCl seal reproduces it exactly and
    /// is NOT equal to the IETF box. Both invariants are asserted.
    #[test]
    fn es_v2_seal_matches_libsodium_crypto_secretbox_xchacha20poly1305_kat() {
        // Decode hex without a hex dep: a tiny inline parser keeps this test self-contained.
        fn unhex(s: &str) -> Vec<u8> {
            let b = s.as_bytes();
            let mut out = Vec::with_capacity(b.len() / 2);
            let v = |c: u8| -> u8 {
                match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => panic!("bad hex"),
                }
            };
            let mut i = 0;
            while i < b.len() {
                out.push((v(b[i]) << 4) | v(b[i + 1]));
                i += 2;
            }
            out
        }

        // --- libsodium crypto_secretbox_xchacha20poly1305 reference vector ---
        // (RustCrypto crypto_secretbox 0.1.1 tests/lib.rs — KEY/NONCE/PLAINTEXT + XChaCha CIPHERTEXT.)
        let key: [u8; 32] =
            unhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
                .try_into()
                .unwrap();
        let nonce: [u8; FULL_NONCE_LEN] = unhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
            .try_into()
            .unwrap();
        let plaintext = unhex(concat!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a",
            "1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057",
            "e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040",
            "e082f937763848645e0705",
        ));
        // The EXACT libsodium box: tag(16) || ciphertext, MAC over the ciphertext only.
        let expected = unhex(concat!(
            "0c61fcffbc3fc8d3aa7464b91ab35374bf8af3198585e55d9cb07edcd1e5a69526547fbd0f2c642e",
            "9ee96e19462031f1032f1cd862bb952900103c06ac16344d7f9c9df0feaaf5a733dea7ea2df70a61",
            "9936fcc5501de75c5d112e8abd7573c461ada29ec016d131aa557804320011ff6d94092581ceea1b",
            "ad3cf0d651938802ca867cd52bbe50c2da1161cb09514407609920",
        ));

        // (1) Our es-v2 seal reproduces the libsodium NaCl box byte-for-byte.
        let ours = aead_seal(ES_XCHACHA, &key, &nonce, &plaintext).expect("es-v2 seal");
        assert_eq!(
            ours, expected,
            "es-v2 must equal the libsodium crypto_secretbox_xchacha box"
        );
        assert_eq!(
            ours.len(),
            AEAD_TAG_LEN + plaintext.len(),
            "tag(16)||ciphertext length"
        );

        // (2) Decisive negative: the IETF chacha20poly1305 box is DIFFERENT (different MAC = length
        // block) — proving we are on the NaCl construction, not the IETF one. (FAIL-before: the old
        // es-v2 seal carried the IETF tag, so its tag bytes equalled the IETF box's tag.)
        let ietf = {
            use chacha20poly1305::aead::{Aead as IetfAead, KeyInit as IetfKeyInit};
            use chacha20poly1305::XChaCha20Poly1305 as IetfX;
            let cipher = IetfX::new_from_slice(&key).expect("ietf key");
            cipher
                .encrypt((&nonce).into(), plaintext.as_slice())
                .expect("ietf seal")
        };
        // IETF is ciphertext||tag; the NaCl tag (front 16 of `ours`) MUST NOT equal the IETF tag (tail
        // 16 of `ietf`). If they matched, we would still be on the IETF MAC (the surviving bug).
        let nacl_tag = &ours[..AEAD_TAG_LEN];
        let ietf_tag = &ietf[plaintext.len()..];
        assert_ne!(
            nacl_tag, ietf_tag,
            "es-v2 MAC must be NaCl (ct-only), not the IETF length-block MAC"
        );
        assert_ne!(
            ours, ietf,
            "es-v2 box must not be the IETF chacha20poly1305 box"
        );

        // (3) Round-trips through our own open (the inverse NaCl construction).
        let opened = aead_open(ES_XCHACHA, &key, &nonce, &ours).expect("es-v2 open");
        assert_eq!(
            opened, plaintext,
            "es-v2 open is the inverse of the NaCl seal"
        );
    }

    /// es-v1 likewise must be the NaCl `crypto_secretbox` (XSalsa20Poly1305) box, byte-for-byte. The
    /// vector is NaCl's own `tests/secretbox.c` answer (same KEY/NONCE/PLAINTEXT as above), via
    /// RustCrypto `crypto_secretbox 0.1.1` `tests/lib.rs`. Confirms both es-versions ride ONE consistent
    /// NaCl path.
    #[test]
    fn es_v1_seal_matches_nacl_crypto_secretbox_xsalsa20poly1305_kat() {
        fn unhex(s: &str) -> Vec<u8> {
            let b = s.as_bytes();
            let mut out = Vec::with_capacity(b.len() / 2);
            let v = |c: u8| -> u8 {
                match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    _ => panic!("bad hex"),
                }
            };
            let mut i = 0;
            while i < b.len() {
                out.push((v(b[i]) << 4) | v(b[i + 1]));
                i += 2;
            }
            out
        }
        let key: [u8; 32] =
            unhex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
                .try_into()
                .unwrap();
        let nonce: [u8; FULL_NONCE_LEN] = unhex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
            .try_into()
            .unwrap();
        let plaintext = unhex(concat!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a",
            "1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057",
            "e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040",
            "e082f937763848645e0705",
        ));
        let expected = unhex(concat!(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4",
            "476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738",
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de",
            "56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
        ));
        let ours = aead_seal(ES_XSALSA, &key, &nonce, &plaintext).expect("es-v1 seal");
        assert_eq!(
            ours, expected,
            "es-v1 must equal the NaCl crypto_secretbox_xsalsa box"
        );
        let opened = aead_open(ES_XSALSA, &key, &nonce, &ours).expect("es-v1 open");
        assert_eq!(opened, plaintext);
    }

    /// Cross-version invariant: both es-versions place the Poly1305 tag in the SAME position
    /// (prepended), since both now route through the NaCl `crypto_secretbox` construction (FIX 1). We
    /// prove the tag is at the FRONT for BOTH by tampering byte 0 (a TAG byte in a tag-prepended box)
    /// and confirming the open fails — and that the byte right after the tag (the first ciphertext
    /// byte) also fails — for each version. (In a ciphertext||tag layout, byte 0 would be a ciphertext
    /// byte and the tag would be at the tail; this asymmetry is what the test pins.)
    #[test]
    fn both_es_versions_prepend_the_tag_identically() {
        let key = [0x5Au8; 32];
        let nonce = [0xA5u8; FULL_NONCE_LEN];
        let msg = b"position-pinned payload bytes";
        for es in [ES_XCHACHA, ES_XSALSA] {
            let sealed = aead_seal(es, &key, &nonce, msg).expect("seal");
            // Total layout is tag(16) || ct(msg.len()).
            assert_eq!(
                sealed.len(),
                AEAD_TAG_LEN + msg.len(),
                "es {es}: tag(16)||ciphertext length"
            );
            // Flipping byte 0 (inside the prepended TAG) breaks authentication.
            let mut t0 = sealed.clone();
            t0[0] ^= 0x01;
            assert!(
                aead_open(es, &key, &nonce, &t0).is_err(),
                "es {es}: byte 0 is a tag byte"
            );
            // Flipping the first CIPHERTEXT byte (just past the 16-byte tag) also breaks it.
            let mut tc = sealed.clone();
            tc[AEAD_TAG_LEN] ^= 0x01;
            assert!(
                aead_open(es, &key, &nonce, &tc).is_err(),
                "es {es}: ciphertext starts at 16"
            );
        }
    }

    // ---- FIX 2 — the UDP TC-bit check must NOT misfire on an encrypted reply ----

    /// An encrypted DNSCrypt reply starts with the resolver magic `r6fnvWj8`, so its byte[2] is `'f'`
    /// (0x66) and `0x66 & 0x02 == 0x02` — i.e. the DNS TC bit reads as "set" on EVERY encrypted reply.
    /// Before FIX 2, `udp_then_tcp` peeked byte[2] unconditionally and so forced a redundant TCP
    /// re-query on every encrypted answer (doubled latency; a hard failure where TCP is firewalled).
    /// FIX 2 gates the TC check to the plaintext cert-fetch path. This pins the decision predicate.
    #[test]
    fn encrypted_reply_is_never_treated_as_truncated() {
        // A realistically shaped encrypted reply: magic || 24-byte nonce || 16-byte tag (minimum).
        let mut enc_reply = Vec::new();
        enc_reply.extend_from_slice(&RESOLVER_MAGIC); // "r6fnvWj8" — byte[2] = 'f' = 0x66
        enc_reply.extend_from_slice(&[0u8; FULL_NONCE_LEN]);
        enc_reply.extend_from_slice(&[0u8; AEAD_TAG_LEN]);
        // Smoking gun: byte[2] of an encrypted reply has the 0x02 bit set (it is the magic, not TC).
        assert_eq!(enc_reply[2], b'f');
        assert_ne!(
            enc_reply[2] & 0x02,
            0,
            "magic byte[2] trips the old TC peek"
        );
        // FIX 2: on the ENCRYPTED path we must NOT retry over TCP, despite byte[2]&0x02 != 0.
        assert!(
            !should_retry_over_tcp(ReplyKind::EncryptedDnsCrypt, &enc_reply),
            "an encrypted-magic UDP reply must NOT be treated as truncated (no spurious TCP re-query)"
        );

        // And the PLAINTEXT cert-fetch path still honours a genuine TC bit (no regression).
        // A DNS header with TC set: id(2) || flags(0x8200 → QR=1,TC=1) || counts...
        let mut truncated_dns = vec![0x00, 0x00, 0x82, 0x00];
        truncated_dns.extend_from_slice(&[0u8; 8]); // rest of a 12-byte header
        assert_ne!(
            truncated_dns[2] & 0x02,
            0,
            "TC bit is set in this plaintext header"
        );
        assert!(
            should_retry_over_tcp(ReplyKind::PlaintextDns, &truncated_dns),
            "a plaintext DNS reply with TC set MUST retry over TCP"
        );
        // A plaintext reply WITHOUT TC is taken from UDP.
        let untruncated_dns = vec![0x00, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(
            !should_retry_over_tcp(ReplyKind::PlaintextDns, &untruncated_dns),
            "a plaintext DNS reply without TC is accepted from UDP"
        );
    }

    // ---- T15 CSPRNG nonce: two consecutive nonces differ ----

    #[test]
    fn two_consecutive_client_nonces_differ() {
        let mut a = [0u8; HALF_NONCE_LEN];
        let mut b = [0u8; HALF_NONCE_LEN];
        csprng_fill(&mut a).expect("csprng a");
        csprng_fill(&mut b).expect("csprng b");
        // A CSPRNG MUST NOT hand out the same 12 bytes twice in a row (T15: never reused).
        assert_ne!(a, b, "consecutive CSPRNG client nonces must differ");
    }

    // ---- full datapath round-trip (no network): derive key, seal, frame, decrypt ----

    #[test]
    fn decrypt_response_round_trips_against_a_forged_resolver_reply() {
        // Stand up both sides of the X25519 box and a forged resolver reply, proving the magic +
        // nonce-echo checks and the AEAD-open + unpad all line up. No socket involved.
        let mut client_sk = [0u8; 32];
        csprng_fill(&mut client_sk).unwrap();
        let client_secret = StaticSecret::from(client_sk);
        let client_pk = PublicKey::from(&client_secret);

        let mut resolver_sk = [0u8; 32];
        csprng_fill(&mut resolver_sk).unwrap();
        let resolver_secret = StaticSecret::from(resolver_sk);
        let resolver_pk = PublicKey::from(&resolver_secret);

        // Both sides derive the SAME shared key (X25519 is symmetric; derive_shared_key is too).
        let client_point = client_secret.diffie_hellman(&resolver_pk).to_bytes();
        let server_point = resolver_secret.diffie_hellman(&client_pk).to_bytes();
        assert_eq!(client_point, server_point, "x25519 is symmetric");
        let key = derive_shared_key(ES_XCHACHA, &client_point).unwrap();

        let client_half = [0x11u8; HALF_NONCE_LEN];
        // The "resolver" builds a reply: magic || client_half || server_half || AEAD(padded answer).
        let inner = b"\x12\x34\x81\x80 a real dns answer would be here";
        let padded = pad_query(inner);
        let mut reply_nonce = [0u8; FULL_NONCE_LEN];
        reply_nonce[..HALF_NONCE_LEN].copy_from_slice(&client_half);
        reply_nonce[HALF_NONCE_LEN..].copy_from_slice(&[0x99u8; HALF_NONCE_LEN]); // server half
        let sealed = aead_seal(ES_XCHACHA, &key, &reply_nonce, &padded).unwrap();

        let mut reply = Vec::new();
        reply.extend_from_slice(&RESOLVER_MAGIC);
        reply.extend_from_slice(&reply_nonce);
        reply.extend_from_slice(&sealed);

        let out = decrypt_response(ES_XCHACHA, &key, &client_half, &reply).expect("decrypt");
        assert_eq!(
            out, inner,
            "the inner DNS bytes come back exactly (opaque to us)"
        );
    }

    #[test]
    fn decrypt_response_rejects_bad_magic_and_nonce_echo() {
        let key = [0x42u8; 32];
        let client_half = [0x11u8; HALF_NONCE_LEN];
        let mut reply_nonce = [0u8; FULL_NONCE_LEN];
        reply_nonce[..HALF_NONCE_LEN].copy_from_slice(&client_half);
        let sealed = aead_seal(ES_XCHACHA, &key, &reply_nonce, &pad_query(b"x")).unwrap();

        // Wrong magic → rejected.
        let mut bad_magic = Vec::new();
        bad_magic.extend_from_slice(b"XXXXXXXX");
        bad_magic.extend_from_slice(&reply_nonce);
        bad_magic.extend_from_slice(&sealed);
        assert!(decrypt_response(ES_XCHACHA, &key, &client_half, &bad_magic).is_err());

        // Right magic but the echoed client nonce half is wrong → rejected (off-path defense).
        let mut wrong_echo_nonce = reply_nonce;
        wrong_echo_nonce[0] ^= 0xFF;
        let sealed2 = aead_seal(ES_XCHACHA, &key, &wrong_echo_nonce, &pad_query(b"x")).unwrap();
        let mut bad_echo = Vec::new();
        bad_echo.extend_from_slice(&RESOLVER_MAGIC);
        bad_echo.extend_from_slice(&wrong_echo_nonce);
        bad_echo.extend_from_slice(&sealed2);
        assert!(decrypt_response(ES_XCHACHA, &key, &client_half, &bad_echo).is_err());
    }

    // ---- HSalsa20 / HChaCha20 known-answer vectors (RFC 7539 / libsodium) ----

    #[test]
    fn hchacha20_matches_rfc7539_test_vector() {
        // RFC 7539 §2.2.1 HChaCha20 test vector.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let input: [u8; 16] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x31, 0x41,
            0x59, 0x27,
        ];
        let expected: [u8; 32] = [
            0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe, 0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87,
            0x7d, 0x73, 0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53, 0xc1, 0x2e, 0xc4, 0x13,
            0x26, 0xd3, 0xec, 0xdc,
        ];
        assert_eq!(hchacha20(&key, &input), expected);
    }

    #[test]
    fn hsalsa20_matches_libsodium_test_vector() {
        // libsodium crypto_core_hsalsa20 reference vector (firstkey).
        let key: [u8; 32] = [
            0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a,
            0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08,
            0x44, 0xf6, 0x83, 0x89,
        ];
        let input: [u8; 16] = [
            0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc,
            0x73, 0xd6,
        ];
        let expected: [u8; 32] = [
            0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b, 0x73, 0x38, 0x20,
            0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e,
            0x66, 0x25, 0x6c, 0xe4,
        ];
        assert_eq!(hsalsa20(&key, &input), expected);
    }

    #[test]
    fn base64url_round_trips() {
        for data in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"\x00\xff\x10"[..],
        ] {
            let enc = base64url_encode(data);
            assert_eq!(
                base64url_decode(&enc).as_deref(),
                Some(data),
                "round-trip {data:?}"
            );
        }
    }

    // ---- ODoH stamp decode (0x05 target / 0x85 relay) ----

    /// Push a length-prefixed (`LP`) field: a `u8` length byte then the bytes.
    #[cfg(feature = "odoh")]
    fn push_lp(body: &mut Vec<u8>, s: &[u8]) {
        body.push(s.len() as u8);
        body.extend_from_slice(s);
    }

    #[cfg(feature = "odoh")]
    #[test]
    fn decodes_odoh_target_stamp() {
        // 0x05 || props(8) || LP host || LP path
        let mut body = vec![0x05u8];
        body.extend_from_slice(&0u64.to_le_bytes());
        push_lp(&mut body, b"odoh.cloudflare-dns.com");
        push_lp(&mut body, b"/dns-query");
        let stamp = format!("{SDNS_PREFIX}{}", base64url_encode(&body));

        assert_eq!(stamp_proto_label(&stamp), "odoh");
        let (host, path) = parse_odoh_target_stamp(&stamp).expect("0x05 must decode");
        assert_eq!(host, "odoh.cloudflare-dns.com");
        assert_eq!(path, "/dns-query");
        // A 0x85 relay stamp is NOT a target — the target parser rejects it.
        assert!(parse_odoh_relay_stamp(&stamp).is_none());
    }

    #[cfg(feature = "odoh")]
    #[test]
    fn decodes_odoh_relay_stamp_skipping_hashes() {
        // 0x85 || props(8) || LP addr || VLP hashes(2 entries) || LP host || LP path
        let mut body = vec![0x85u8];
        body.extend_from_slice(&0u64.to_le_bytes());
        push_lp(&mut body, b""); // empty bootstrap addr (dial by hostname)
                                  // VLP hashes: first entry has the 0x80 continuation bit set, second clears it.
        let h = [0xABu8; 32];
        body.push(0x80 | 32);
        body.extend_from_slice(&h);
        body.push(32); // last hash, continuation bit clear
        body.extend_from_slice(&h);
        push_lp(&mut body, b"odoh1.surfdomeinen.nl");
        push_lp(&mut body, b"/proxy");
        let stamp = format!("{SDNS_PREFIX}{}", base64url_encode(&body));

        assert_eq!(stamp_proto_label(&stamp), "odoh-relay");
        let (host, path) = parse_odoh_relay_stamp(&stamp).expect("0x85 must decode past the hashes");
        assert_eq!(host, "odoh1.surfdomeinen.nl");
        assert_eq!(path, "/proxy");
        // A 0x85 relay stamp is NOT a target.
        assert!(parse_odoh_target_stamp(&stamp).is_none());
    }

    // ---- R2 protect infrastructure (task 1E) ----

    /// A test-only [`ProtectCallback`] that records the fds it was asked to protect and returns the
    /// `accept` flag. Mirrors the Kotlin `vpnService.protect(fd)` impl's contract.
    struct RecordingProtect {
        accept: bool,
        seen: std::sync::Mutex<Vec<i32>>,
    }

    impl ProtectCallback for RecordingProtect {
        fn protect_fd(&self, fd: i32) -> bool {
            self.seen.lock().unwrap().push(fd);
            self.accept
        }
    }

    /// `protect_callback_installed` reflects the installed/cleared state. `install_protect_callback`
    /// is the TunnelController-facing setter; here we exercise the install/clear cycle + the
    /// `installed` predicate so the pub API is covered and the guard wiring is end-to-end on the host.
    #[test]
    fn protect_callback_install_and_clear_cycle() {
        // Start from a clean slate (a prior test in this process may have installed one).
        install_protect_callback(None);
        assert!(!protect_callback_installed());

        let cb = Arc::new(RecordingProtect {
            accept: true,
            seen: std::sync::Mutex::new(Vec::new()),
        });
        install_protect_callback(Some(cb));
        assert!(protect_callback_installed());

        // A VPN down/up cycle clears + re-installs (R2 rebuild contract).
        install_protect_callback(None);
        assert!(!protect_callback_installed());

        // Leave the process-global clean for subsequent tests.
        install_protect_callback(None);
    }

    /// On the host build `protect_raw_fd` is the documented no-op (no VPN). The guarded transports
    /// call it before connect/sendto; with no callback installed it MUST be `Ok(())` (the byte-identical
    /// pre-1E path). This pins the no-op invariant that keeps the host datapath unchanged.
    #[test]
    fn protect_raw_fd_is_noop_with_no_callback_installed() {
        install_protect_callback(None);
        assert!(
            protect_raw_fd(-1).is_ok(),
            "no callback ⇒ Ok (host datapath)"
        );
        // Clean up (defensive — no callback was installed, but be explicit for test isolation).
        install_protect_callback(None);
    }

    // -----------------------------------------------------------------------------------------------
    // ★ PQDNSCrypt (es-0x0003) — the X-Wing corpus. The Appendix-3 test pins this implementation to
    // the DRAFT SPEC's own vectors (the same anchor upstream pq_test.go:33-119 validates against), so
    // key schedule + AEAD + framing are proven against EXTERNAL truth, not self-consistency.
    // -----------------------------------------------------------------------------------------------

    /// Test-only hex decoder (the vectors are pinned as hex strings, as in the draft's appendix).
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("test vector hex"))
            .collect()
    }

    /// `n` bytes counting up from `start` — the draft's deterministic seed convention
    /// (upstream `iotaBytes`, pq_test.go:15-21).
    fn iota_bytes<const N: usize>(start: u8) -> [u8; N] {
        let mut b = [0u8; N];
        for (i, v) in b.iter_mut().enumerate() {
            *v = start.wrapping_add(i as u8);
        }
        b
    }

    /// Build a PQ (1320-byte) cert and Ed25519-SIGN its signed region — the PQ twin of
    /// `make_signed_cert`. Header es, the extension bytes, and every signed field are
    /// caller-controlled so the tamper tests can flip them independently.
    #[allow(clippy::too_many_arguments)]
    fn make_signed_pq_cert(
        signing: &ed25519_dalek::SigningKey,
        es_version: u16,
        xwing_pk: &[u8],
        client_magic: &[u8; 8],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
        ext: &[u8; 12],
    ) -> Vec<u8> {
        use ed25519_dalek::Signer;
        assert_eq!(xwing_pk.len(), PQ_XWING_PK_LEN, "test pk must be X-Wing sized");
        // Signed region: pk(1216) || client-magic(8) || serial(4) || ts_start(4) || ts_end(4) || ext(12).
        let mut signed = Vec::with_capacity(PQ_CERT_LEN - 72);
        signed.extend_from_slice(xwing_pk);
        signed.extend_from_slice(client_magic);
        signed.extend_from_slice(&serial.to_be_bytes());
        signed.extend_from_slice(&ts_start.to_be_bytes());
        signed.extend_from_slice(&ts_end.to_be_bytes());
        signed.extend_from_slice(ext);

        let sig = signing.sign(&signed);

        let mut cert = Vec::with_capacity(PQ_CERT_LEN);
        cert.extend_from_slice(&CERT_MAGIC);
        cert.extend_from_slice(&es_version.to_be_bytes());
        cert.extend_from_slice(&0u16.to_be_bytes()); // protocol minor
        cert.extend_from_slice(&sig.to_bytes());
        cert.extend_from_slice(&signed);
        assert_eq!(cert.len(), PQ_CERT_LEN);
        cert
    }

    /// ★ THE anchor — Appendix 3 of the PQDNSCrypt draft, the pinned vectors upstream pq_test.go
    /// validates the same client legs against: X-Wing keygen from seed, deterministic encapsulation,
    /// the HKDF cert-bound shared key, the sealed query, and the full wire frame. Byte equality here
    /// proves (a) the x-wing crate matches cloudflare/circl, (b) `pq_derive_shared_key` +
    /// `build_pq_cert_context` mirror pq.go, and (c) `crypto_secretbox` XChaCha20 == Go `xsecretbox`
    /// on the PQ path. (The resume-secret / resumed-query vectors are NOT ported: Tortä deliberately
    /// never sends resumed queries — see `pq_strip_control` — so there is no resume code to pin.)
    #[test]
    fn pq_appendix3_draft_vectors() {
        use sha2::Digest;
        use x_wing::{Decapsulator, DecapsulationKey, KeyExport};

        let client_magic: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
        let dns_query =
            unhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001");

        // X-Wing keygen from the deterministic 32-byte seed (draft: rseed = 0x20..0x3f).
        let dk = DecapsulationKey::from(iota_bytes::<32>(0x20));
        let ek = dk.encapsulation_key();
        let pk_bytes = ek.to_bytes();
        assert_eq!(
            sha2::Sha256::digest(&pk_bytes[..])[..],
            unhex("a1f324bc0701f1234fbba7b11901023b3644f3bb8c6eb4ee4368d7e859eb6228")[..],
            "resolver X-Wing pk (sha256) must match the draft vector"
        );

        // Deterministic encapsulation (draft: eseed = 0x40..0x7f).
        let (ct, kem_ss) = ek.encapsulate_deterministic(&iota_bytes::<64>(0x40).into());
        assert_eq!(
            kem_ss[..],
            unhex("8dac8602d4ce5e27e81335b54b25fdcaea86e56613214ee0522db4a5e0a38d50")[..],
            "X-Wing shared secret must match the draft vector"
        );

        // The 1320-byte cert the context binds to (pq_test.go:54-62 — unsigned fields zero).
        let mut cert = vec![0u8; PQ_CERT_LEN];
        cert[0..4].copy_from_slice(&CERT_MAGIC);
        cert[4..6].copy_from_slice(&ES_XWING_PQ.to_be_bytes());
        cert[72..1288].copy_from_slice(&pk_bytes[..]);
        cert[1288..1296].copy_from_slice(&client_magic);
        cert[1296..1300].copy_from_slice(&1u32.to_be_bytes());
        cert[1300..1304].copy_from_slice(&[0x68, 0x00, 0x00, 0x00]);
        cert[1304..1308].copy_from_slice(&[0x68, 0x01, 0x51, 0x80]);
        cert[1308..1320].copy_from_slice(&PQ_PROFILE_EXT);

        let ctx = build_pq_cert_context(&cert);
        let shared_key = pq_derive_shared_key(&kem_ss[..], &client_magic, &ctx, &ct[..]);
        assert_eq!(
            shared_key[..],
            unhex("e6d4ab9cffc9b49e2a64d80d7eb2dde280f806b89e834d596ad385b1dd75e9ef")[..],
            "HKDF cert-bound shared key must match the draft vector"
        );

        // Padded fresh query: floor 64 exactly fits the 33-byte query + 0x80.
        let padded = pq_pad(&dns_query, PQ_FRESH_PAD_FLOOR);
        assert_eq!(padded.len(), 64, "draft: padded fresh query is one block");

        // Seal under nonce = qNonce(12, 0xb0..) || 0¹² — proves crypto_secretbox == Go xsecretbox.
        let q_nonce = iota_bytes::<12>(0xb0);
        let mut nonce24 = [0u8; FULL_NONCE_LEN];
        nonce24[..HALF_NONCE_LEN].copy_from_slice(&q_nonce);
        let enc_query =
            aead_seal(ES_XCHACHA, &shared_key, &nonce24, &padded).expect("seal");
        assert_eq!(
            enc_query[..],
            unhex(
                "c41764468cb42d3a837c51234c08be714af49e1a6830ea6da28178e9e280d76bac1b87fd7f56515f2b2cc3d4715aaa42907c282db1edff0bc3b92cd535a710e264859a5bdaf67c17ffa6e1c6f6e02a50"
            )[..],
            "sealed query must match the draft vector (NaCl XChaCha20 secretbox, tag-first)"
        );

        // Full wire frame: <client-magic><x-wing ct><nonce-half><sealed> — 1220 bytes pinned.
        let mut frame = Vec::new();
        frame.extend_from_slice(&client_magic);
        frame.extend_from_slice(&ct[..]);
        frame.extend_from_slice(&q_nonce);
        frame.extend_from_slice(&enc_query);
        assert_eq!(frame.len(), 1220, "draft: full fresh-query frame length");
        assert_eq!(
            sha2::Sha256::digest(&frame)[..],
            unhex("65c3421776283f503779916e7b5c32d0d41c885508ad892b349688db6c901233")[..],
            "full query wire (sha256) must match the draft vector"
        );
    }

    /// A validly-signed PQ cert parses with its material intact, from the PQ offsets.
    #[test]
    fn pq_cert_parses_material_from_pq_offsets() {
        use x_wing::{Decapsulator, DecapsulationKey, KeyExport};
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let dk = DecapsulationKey::from(iota_bytes::<32>(0x20));
        let pk = dk.encapsulation_key().to_bytes();

        let cert = make_signed_pq_cert(
            &signing,
            ES_XWING_PQ,
            &pk[..],
            b"PQMAGIC!",
            7,
            50,
            150,
            &PQ_PROFILE_EXT,
        );
        let parsed = parse_cert(&cert).expect("valid PQ cert parses");
        assert_eq!(parsed.es_version, ES_XWING_PQ);
        assert_eq!(parsed.client_magic, *b"PQMAGIC!");
        assert_eq!(parsed.serial, 7);
        assert_eq!((parsed.ts_start, parsed.ts_end), (50, 150));
        assert_eq!(parsed.resolver_pk, [0u8; 32], "classic pk slot is the zero placeholder");
        let pq = parsed.pq.expect("PQ material present");
        assert_eq!(pq.pk[..], pk[..]);
        assert_eq!(
            pq.cert_context,
            build_pq_cert_context(&cert),
            "context precomputed from the exact cert bytes"
        );
    }

    /// FIX 2, PQ edition — flipped headers are rejected on SIGNED evidence, both directions:
    /// (a) a PQ cert whose unsigned header claims classic es-2 (the signed PQ profile outs it), and
    /// (b) a header claiming es-0x0003 without the signed PQ profile behind it.
    #[test]
    fn pq_flipped_header_rejected_both_directions() {
        use x_wing::{Decapsulator, DecapsulationKey, KeyExport};
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let dk = DecapsulationKey::from(iota_bytes::<32>(0x20));
        let pk = dk.encapsulation_key().to_bytes();

        // (a) genuine PQ cert, header flipped to es-2 AFTER signing (the flip is unsigned).
        let mut flipped =
            make_signed_pq_cert(&signing, ES_XWING_PQ, &pk[..], b"PQMAGIC!", 7, 50, 150, &PQ_PROFILE_EXT);
        flipped[4..6].copy_from_slice(&ES_XCHACHA.to_be_bytes());
        assert!(
            parse_cert(&flipped).is_none(),
            "signed PQ profile + classic header = downgrade fingerprint → reject"
        );

        // (b) PQ-claiming header with a corrupted profile extension.
        let mut bad_ext = PQ_PROFILE_EXT;
        bad_ext[6] = 0x02; // wrong KDF id
        let cert = make_signed_pq_cert(&signing, ES_XWING_PQ, &pk[..], b"PQMAGIC!", 7, 50, 150, &bad_ext);
        assert!(
            parse_cert(&cert).is_none(),
            "es-0x0003 header without the exact signed PQ profile → reject"
        );
    }

    /// The es-major selection law crosses the PQ boundary: a valid PQ cert beats a valid classic
    /// es-2 cert (even a fresher-serial one), and the `pqdnscrypt` gate flips the outcome back to
    /// classic without touching the certs.
    #[test]
    fn pq_selection_beats_classic_and_gate_disables() {
        use x_wing::{Decapsulator, DecapsulationKey, KeyExport};
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();
        let dk = DecapsulationKey::from(iota_bytes::<32>(0x20));
        let xpk = dk.encapsulation_key().to_bytes();

        let classic = make_signed_cert_serial(
            &signing,
            ES_XCHACHA,
            &[7u8; 32],
            b"CLASSIC!",
            99, // fresher serial than the PQ cert — es-major must still prefer PQ
            50,
            150,
        );
        let pq = make_signed_pq_cert(&signing, ES_XWING_PQ, &xpk[..], b"PQMAGIC!", 1, 50, 150, &PQ_PROFILE_EXT);

        let best = select_best_cert(&[classic.clone(), pq.clone()], &provider_pk, 100, true)
            .expect("a valid cert");
        assert_eq!(best.es_version, ES_XWING_PQ, "PQ wins the es-major order");
        assert_eq!(best.client_magic, *b"PQMAGIC!");
        assert!(best.pq.is_some(), "material rides the cache");

        let gated = select_best_cert(&[classic, pq], &provider_pk, 100, false)
            .expect("classic cert still valid with PQ gated off");
        assert_eq!(gated.es_version, ES_XCHACHA, "pqdnscrypt=false skips es-0x0003");
        assert!(gated.pq.is_none());
    }

    /// `pq_pad` floors and the shared ISO 7816-4 unpad roundtrip.
    #[test]
    fn pq_pad_floors_and_roundtrip() {
        let q = vec![0xAB; 33];
        let fresh = pq_pad(&q, PQ_FRESH_PAD_FLOOR);
        assert_eq!(fresh.len(), 64, "33 + 0x80 rounds into one block");
        assert_eq!(unpad_response(fresh).expect("roundtrip"), q);

        let resumed_floor = pq_pad(&q, 256);
        assert_eq!(resumed_floor.len(), 256, "floor lifts short queries to 256");
        assert_eq!(unpad_response(resumed_floor).expect("roundtrip"), q);

        let exact = pq_pad(&vec![1u8; 63], PQ_FRESH_PAD_FLOOR);
        assert_eq!(exact.len(), 64, "63 + delimiter = exactly one block, no extra block");

        let spill = pq_pad(&vec![1u8; 64], PQ_FRESH_PAD_FLOOR);
        assert_eq!(spill.len(), 128, "64 + delimiter spills into the next block");
    }

    /// Control-block strip: empty control, a ticket-bearing control (ignored but correctly
    /// stripped), and the malformed shapes (overflow / short) that must reject the reply.
    #[test]
    fn pq_control_strip_shapes() {
        // Empty control block (len 0) — the common no-ticket reply.
        let mut plain = vec![0x00, 0x00];
        plain.extend_from_slice(&pq_pad(b"body", PQ_FRESH_PAD_FLOOR));
        let body = pq_strip_control(plain).expect("empty control strips");
        assert_eq!(unpad_response(body).expect("unpad"), b"body");

        // Ticket-bearing control ("PQDR" + version + lifetime + ticket) — stripped, ticket IGNORED.
        let mut control = Vec::new();
        control.extend_from_slice(&PQ_CONTROL_MAGIC);
        control.push(0x01); // control version
        control.extend_from_slice(&60u32.to_be_bytes()); // lifetime
        control.extend_from_slice(&6u16.to_be_bytes()); // ticket len
        control.extend_from_slice(b"ticket");
        let mut plain = Vec::new();
        plain.extend_from_slice(&(control.len() as u16).to_be_bytes());
        plain.extend_from_slice(&control);
        plain.extend_from_slice(&pq_pad(b"answer", PQ_FRESH_PAD_FLOOR));
        let body = pq_strip_control(plain).expect("ticket control strips");
        assert_eq!(unpad_response(body).expect("unpad"), b"answer");

        // Overflowing control length → reject.
        assert!(pq_strip_control(vec![0xFF, 0xFF, 0x00]).is_none());

        // A NON-EMPTY control block whose magic is not ours → reject. The body is already
        // AEAD-authenticated, so this is not a forgery: it is a resolver speaking a control-block
        // format we do not know, and draining bytes of an unrecognised format would hand the
        // unpadder a body starting somewhere we cannot justify.
        let mut wrong = Vec::new();
        let bad_control = b"XXXXv1";
        wrong.extend_from_slice(&(bad_control.len() as u16).to_be_bytes());
        wrong.extend_from_slice(bad_control);
        wrong.extend_from_slice(&pq_pad(b"answer", PQ_FRESH_PAD_FLOOR));
        assert!(
            pq_strip_control(wrong).is_none(),
            "an unrecognised control-block format must be refused, not silently stripped"
        );

        // A non-empty block too short to even carry the magic → reject.
        let mut stub = Vec::new();
        stub.extend_from_slice(&2u16.to_be_bytes());
        stub.extend_from_slice(b"PQ");
        stub.extend_from_slice(&pq_pad(b"answer", PQ_FRESH_PAD_FLOOR));
        assert!(
            pq_strip_control(stub).is_none(),
            "a non-empty control block shorter than the magic it must begin with is malformed"
        );

        // NON-VACUITY: the SAME shape with the correct magic is still accepted, so the two
        // assertions above are discriminating on the magic and not on the length.
        let mut good = Vec::new();
        let mut good_control = PQ_CONTROL_MAGIC.to_vec();
        good_control.extend_from_slice(b"v1");
        good.extend_from_slice(&(good_control.len() as u16).to_be_bytes());
        good.extend_from_slice(&good_control);
        good.extend_from_slice(&pq_pad(b"answer", PQ_FRESH_PAD_FLOOR));
        let body = pq_strip_control(good).expect("our own magic is accepted at the same length");
        assert_eq!(unpad_response(body).expect("unpad"), b"answer");
        // Shorter than the length prefix → reject.
        assert!(pq_strip_control(vec![0x00]).is_none());
    }

    /// A swapped ciphertext changes the derived key (the info-binding splice defense).
    #[test]
    fn pq_derive_key_binds_ciphertext() {
        let magic = *b"PQMAGIC!";
        let ctx = b"ctx".to_vec();
        let k1 = pq_derive_shared_key(&[1u8; 32], &magic, &ctx, &[2u8; 8]);
        let k2 = pq_derive_shared_key(&[1u8; 32], &magic, &ctx, &[3u8; 8]);
        assert_ne!(k1, k2, "ct is inside the HKDF info — a splice re-keys");
    }

    /// ★ Full client↔resolver loopback: the client legs run EXACTLY the `pq_encrypted_exchange`
    /// framing; the simulated resolver decapsulates with the X-Wing secret key, derives the SAME
    /// cert-bound key, opens the query, and seals a control-prefixed reply that
    /// `pq_decrypt_response` must accept. Proves both sides of the key schedule agree end-to-end
    /// (encapsulate → HKDF → seal → open → control-strip → unpad), on top of the Appendix-3 pins.
    #[test]
    fn pq_full_loopback_roundtrip() {
        use x_wing::{Decapsulate, Decapsulator, DecapsulationKey, KeyExport};
        let signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let provider_pk = signing.verifying_key().to_bytes();

        // Resolver keypair + published, signed PQ cert.
        let dk = DecapsulationKey::from(iota_bytes::<32>(0x77));
        let xpk = dk.encapsulation_key().to_bytes();
        let cert_bytes =
            make_signed_pq_cert(&signing, ES_XWING_PQ, &xpk[..], b"PQMAGIC!", 1, 50, 150, &PQ_PROFILE_EXT);
        let cert = select_best_cert(&[cert_bytes.clone()], &provider_pk, 100, true)
            .expect("PQ cert selected");
        let pq = cert.pq.as_ref().expect("material");

        // CLIENT — the pq_encrypted_exchange legs (framing only; no network in a unit test).
        let query = unhex("12340100000100000000000003777777076578616d706c6503636f6d0000010001");
        let half_nonce = iota_bytes::<12>(0xC0);
        let ek = XWingEncapsulationKey::try_from(pq.pk.as_slice()).expect("pk parses");
        let (ct, kem_ss) = ek.encapsulate_deterministic(&iota_bytes::<64>(0x55).into());
        let client_key = pq_derive_shared_key(&kem_ss[..], &cert.client_magic, &pq.cert_context, &ct[..]);
        let mut nonce24 = [0u8; FULL_NONCE_LEN];
        nonce24[..HALF_NONCE_LEN].copy_from_slice(&half_nonce);
        let sealed = aead_seal(
            ES_XCHACHA,
            &client_key,
            &nonce24,
            &pq_pad(&query, PQ_FRESH_PAD_FLOOR),
        )
        .expect("seal");
        let mut frame = Vec::new();
        frame.extend_from_slice(&cert.client_magic);
        frame.extend_from_slice(&ct[..]);
        frame.extend_from_slice(&half_nonce);
        frame.extend_from_slice(&sealed);

        // RESOLVER — parse the frame, decapsulate, derive the same key, open the query.
        assert_eq!(&frame[0..8], b"PQMAGIC!");
        let ct_wire = &frame[8..8 + PQ_XWING_CT_LEN];
        let srv_ct = x_wing::Ciphertext::try_from(ct_wire).expect("ct sized");
        let srv_ss = dk.decapsulate(&srv_ct);
        let srv_ctx = build_pq_cert_context(&cert_bytes);
        let srv_key = pq_derive_shared_key(&srv_ss[..], b"PQMAGIC!", &srv_ctx, ct_wire);
        assert_eq!(client_key, srv_key, "both sides derive the SAME cert-bound key");
        let srv_half: &[u8] = &frame[8 + PQ_XWING_CT_LEN..8 + PQ_XWING_CT_LEN + HALF_NONCE_LEN];
        let mut srv_nonce = [0u8; FULL_NONCE_LEN];
        srv_nonce[..HALF_NONCE_LEN].copy_from_slice(srv_half);
        let opened = aead_open(
            ES_XCHACHA,
            &srv_key,
            &srv_nonce,
            &frame[8 + PQ_XWING_CT_LEN + HALF_NONCE_LEN..],
        )
        .expect("resolver opens the query");
        assert_eq!(unpad_response(opened).expect("unpad"), query);

        // RESOLVER reply — control block (with a ticket we must IGNORE) + padded answer, sealed
        // under nonce = client-half || server-half, framed with the resolver magic.
        let answer = b"the-dns-answer".to_vec();
        let mut control = Vec::new();
        control.extend_from_slice(&PQ_CONTROL_MAGIC);
        control.push(0x01);
        control.extend_from_slice(&60u32.to_be_bytes());
        control.extend_from_slice(&4u16.to_be_bytes());
        control.extend_from_slice(b"tkt!");
        let mut reply_plain = Vec::new();
        reply_plain.extend_from_slice(&(control.len() as u16).to_be_bytes());
        reply_plain.extend_from_slice(&control);
        reply_plain.extend_from_slice(&pq_pad(&answer, PQ_FRESH_PAD_FLOOR));
        let mut reply_nonce = [0u8; FULL_NONCE_LEN];
        reply_nonce[..HALF_NONCE_LEN].copy_from_slice(&half_nonce);
        reply_nonce[HALF_NONCE_LEN..].copy_from_slice(&iota_bytes::<12>(0xE0));
        let reply_sealed =
            aead_seal(ES_XCHACHA, &srv_key, &reply_nonce, &reply_plain).expect("reply seal");
        let mut reply = Vec::new();
        reply.extend_from_slice(&RESOLVER_MAGIC);
        reply.extend_from_slice(&reply_nonce);
        reply.extend_from_slice(&reply_sealed);

        // CLIENT — the production decrypt leg accepts it and yields the bare answer.
        let got = pq_decrypt_response(&client_key, &half_nonce, &reply).expect("decrypt");
        assert_eq!(got, answer, "control stripped, ticket ignored, padding removed");

        // Tampers die: a flipped ciphertext byte fails the tag; a wrong echo fails before the AEAD.
        let mut bad = reply.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(pq_decrypt_response(&client_key, &half_nonce, &bad).is_err());
        let wrong_half = iota_bytes::<12>(0x01);
        assert!(pq_decrypt_response(&client_key, &wrong_half, &reply).is_err());
    }

    // ---- ★ 2.1.18-absorb: the PQ cert-fetch lane (`relayed_tcp_then_udp`) ----
    //
    // Loopback servers (the `listener.rs`/`mod.rs` house pattern), zero external network. The lane
    // contract: TCP-first (a PQ cert can never fit the 512-byte no-EDNS0 UDP ceiling), classic
    // UDP+TC ladder ONLY when TCP itself fails (fail-open: a classic-only resolver still answers).

    /// Serve exactly one RFC 7766-framed DNS-over-TCP reply, then close. Returns the bound addr.
    async fn one_shot_tcp_server(reply: Vec<u8>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            if let Ok((mut stream, _)) = listener.accept().await {
                // Read the framed request (len prefix + body), then answer with the canned reply.
                let mut len = [0u8; 2];
                if stream.read_exact(&mut len).await.is_ok() {
                    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
                    let _ = stream.read_exact(&mut body).await;
                }
                let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                let _ = stream.write_all(&framed).await;
            }
        });
        addr
    }

    /// Serve exactly one UDP reply (echoed to whoever sends first), then exit.
    async fn one_shot_udp_server(reply: Vec<u8>) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            if let Ok((_, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&reply, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn pq_cert_lane_fetches_over_tcp_first() {
        // A plaintext DNS reply with TC=0 — over TCP any size arrives whole; the lane must return
        // it verbatim WITHOUT ever touching UDP (there is no UDP server here at all: if the lane
        // dialed UDP first, the exchange would error/hang instead of answering).
        let reply = vec![0x00, 0x00, 0x80, 0x00, 0xEE, 0xFF];
        let addr = one_shot_tcp_server(reply.clone()).await;
        let got = relayed_tcp_then_udp(&[], &addr, &[0x00, 0x00, 0x01, 0x00])
            .await
            .expect("TCP-first lane answers");
        assert_eq!(got, reply, "the framed TCP reply comes back verbatim");
    }

    #[tokio::test]
    async fn pq_cert_lane_falls_back_to_udp_when_tcp_is_dead() {
        // Bind-then-drop a TCP port so the dial RSTs immediately (dead TCP), and stand up a UDP
        // server on the SAME port answering a TC=0 plaintext reply: the lane must fail-open onto
        // the classic UDP+TC ladder and still come home with the answer.
        let reply = vec![0x00, 0x00, 0x80, 0x00, 0xCA, 0xFE];
        let udp_addr = one_shot_udp_server(reply.clone()).await;
        // No TCP listener on udp_addr's port — loopback dial fails fast with ECONNREFUSED.
        let got = relayed_tcp_then_udp(&[], &udp_addr, &[0x00, 0x00, 0x01, 0x00])
            .await
            .expect("UDP fallback answers when TCP is dead");
        assert_eq!(got, reply, "the classic ladder still delivers the cert reply");
    }
}

/// The ANONYMIZED-DNS relay validator (`DnsCrypt::parse_relay_chain`, surfaced to settings as
/// `dnscrypt_relay_check`). The property under test is the one that makes the surface worth having:
/// it must be STRICTER than the configure path, which by documented design accepts a DNSCrypt
/// resolver stamp in the relay field and therefore anonymizes nothing while looking armed.
#[cfg(test)]
mod relay_validator_tests {
    use super::tests::{make_relay_stamp, make_stamp};
    use super::*;

    /// Genuine relay stamps parse, in order, preserving the multi-hop chain.
    #[test]
    fn genuine_relay_stamps_parse_in_order() {
        let a = make_relay_stamp("45.32.55.94:443");
        let b = make_relay_stamp("1.2.3.4:443");
        let chain = DnsCrypt::parse_relay_chain(&[a.as_str(), b.as_str()]);
        assert_eq!(chain.len(), 2, "both relays are accepted");
        assert_eq!(chain[0].to_string(), "45.32.55.94:443", "the chain keeps its order");
        assert_eq!(chain[1].to_string(), "1.2.3.4:443");
    }

    /// THE POINT OF THE SURFACE. A DNSCrypt RESOLVER stamp (0x01) in the relay field is REJECTED
    /// here, while the configure path's `parse_stamp_addr` accepts it. That difference is the whole
    /// user-facing value: a resolver stamp pasted as a relay yields a config that looks armed and
    /// anonymizes NOTHING, and only the strict reading can say so.
    #[test]
    fn a_resolver_stamp_is_rejected_as_a_relay() {
        let resolver_stamp = make_stamp(STAMP_PROTO_DNSCRYPT, "9.9.9.9:443", &[1u8; 32], "p.example");
        // The LENIENT configure path accepts it -- documented behaviour, asserted so this test fails
        // loudly if that leniency is ever changed, rather than silently losing its own premise.
        assert!(
            parse_stamp_addr(&resolver_stamp).is_some(),
            "premise: the configure path is lenient and accepts a resolver stamp as a relay"
        );
        // The STRICT reading refuses it.
        assert!(
            DnsCrypt::parse_relay_chain(&[resolver_stamp.as_str()]).is_empty(),
            "a 0x01 resolver stamp is NOT a relay and must never be counted as one"
        );
    }

    /// Malformed input is dropped rather than panicking, and a partially-bad list keeps its good
    /// entries (matching the Go resolver's lenient `via` handling).
    #[test]
    fn malformed_entries_are_dropped_not_panicked() {
        let good = make_relay_stamp("45.32.55.94:443");
        let inputs = [
            "",
            "not-a-stamp",
            "sdns://",
            "sdns://!!!!not-base64!!!!",
            good.as_str(),
        ];
        let chain = DnsCrypt::parse_relay_chain(&inputs);
        assert_eq!(chain.len(), 1, "only the one genuine relay survives");
        assert_eq!(chain[0].to_string(), "45.32.55.94:443");
    }

    /// Empty input is DIRECT (no relay), never an error — the pre-anonymization default posture.
    #[test]
    fn empty_input_is_direct() {
        assert!(
            DnsCrypt::parse_relay_chain(&[]).is_empty(),
            "no relays supplied means direct, not a failure"
        );
    }

    /// `with_relays` installs the chain THROUGH `set_relays`, so the constructor and the setter
    /// cannot drift. Pinned by observing that both routes produce the same relay state.
    #[test]
    fn with_relays_and_set_relays_agree() {
        let stamp = make_stamp(STAMP_PROTO_DNSCRYPT, "9.9.9.9:443", &[1u8; 32], "p.example");
        let addrs = DnsCrypt::parse_relay_chain(&[make_relay_stamp("45.32.55.94:443").as_str()]);
        assert_eq!(addrs.len(), 1, "fixture sanity: one relay parsed");

        let via_ctor = DnsCrypt::with_relays("a", &stamp, addrs.clone()).expect("ctor");
        let mut via_setter = DnsCrypt::new("a", &stamp).expect("new");
        via_setter.set_relays(addrs.clone());

        assert_eq!(
            via_ctor.relays, via_setter.relays,
            "with_relays must install exactly what set_relays installs"
        );
        assert_eq!(via_ctor.relays, addrs);
    }
}
