# P7 Wave 2 — In-App Rust Resolver: Implementation Plan

> Synthesized by an Ultracode design workflow (4 agents). The blueprint for finishing P7's resolver track.
> Shadow-first, staged, each sub-wave adversarially reviewed + runtime-verified on the x86_64 KVM emulator.

## Verdict (conflicts resolved)
- **Async:** ONE long-lived `tokio` **current-thread** runtime owned by a resolver singleton (battery: parks when idle, no thread-pool on a phone).
- **TLS:** `rustls 0.23` + **`ring`** provider (NOT aws-lc-rs) — cross-compile-safe for Windows-host→cargo-ndk.
- **DoH/DoH3:** hand-wire `hyper`+`hyper-rustls` (DoH) and `quinn`+`h3` (DoH3) — NOT hickory, NOT reqwest. We are a transport multiplexer; `dns.rs` already owns DNS semantics.
- **JNI shape:** process-global **`OnceLock<Resolver>`** singleton + binary `ByteArray→ByteArray` per-query (mirrors `blocklist::INSTALLED`; Kotlin never holds a raw pointer). DNS is bytes — never a Java String round-trip.

## Staged sub-wave sequence (shadow-first)
The resolver ships **shadow**: resolves in parallel with the Go `dnscrypt-proxy`, comparing answers, governing nothing, until it earns primacy by agreeing at volume.

| Sub-wave | Goal |
|---|---|
| **2b** | DoH (HTTP/2) **shadow** — proves the skeleton: runtime + ring/rustls + JNI singleton + `validate_response` + async panic firewall, simplest transport. **START HERE.** |
| **2c** | **QUIC transports shadow** — DoH3 (DNS-over-HTTP/3) **+ DoQ (DNS-over-QUIC, RFC 9250)**: both ride one `quinn` stack + the shared `VpnService.protect()`-ed UDP fd; 0-RTT off; DoQ = 2-byte len-prefix per bidi stream, ID=0; clean fallback to DoH2. |
| **2d** | DNSCrypt v2 client **shadow** — replace-dnscrypt-proxy core: stamp parse, cert fetch + Ed25519 verify + rotation, X25519/XChaCha20, nonce discipline; anonymized relays scaffold. |
| **2e** | Promote to **PRIMARY** + retire dnscrypt-proxy — flip default, blocklist enforces for real, encrypted-only fail-closed ladder, anonymized relays, delete the Go binary (one-version rollback kept). |

## Crate list (June 2026, confirmed) — add to `rust/torta_core/Cargo.toml`
```toml
# Runtime + FFI
jni    = "0.21"                                              # already in tree
tokio  = { version = "1", default-features = false, features = ["rt","net","time","sync","macros"] }  # current-thread ONLY
bytes  = "1"
# TLS core (Android-critical: ring, NOT aws-lc-rs)
rustls = { version = "0.23", default-features = false, features = ["ring","std","tls12"] }
ring   = "0.17"
rustls-platform-verifier = "0.7"                            # Android system trust — MANDATORY android::init_with_env()
webpki-roots = "1"                                          # static fallback + Expert "built-in roots only"
# DoH (HTTP/2, RFC 8484) — workhorse
hyper          = { version = "1", features = ["client","http1","http2"] }
hyper-util     = { version = "0.1", features = ["client-legacy","tokio"] }
hyper-rustls   = { version = "0.27", default-features = false, features = ["http2","ring"] }
http           = "1"
http-body-util = "0.1"
# DoH3 (HTTP/3 / QUIC, RFC 9114) — opt-in, feature = "doh3"
quinn    = { version = "0.11", default-features = false, features = ["ring","runtime-tokio","rustls"] }
h3       = "0.0.8"                                          # pre-1.0 — pin EXACT
h3-quinn = "0.0.9"                                          # pre-1.0 — pin EXACT
# DNSCrypt v2 — hand-rolled (no client crate exists)
x25519-dalek     = { version = "2", features = ["static_secrets"] }
chacha20poly1305 = "0.10"                                   # XChaCha20-Poly1305 (es v2, 24B nonce)
xsalsa20poly1305 = "0.10"                                   # XSalsa20-Poly1305  (es v1, NaCl crypto_box)
ed25519-dalek    = "2"                                      # verify provider-signed cert
dnsstamps        = "0.1"                                    # parse sdns:// (resolver + relay 0x81 stamps)
rand_core = "0.6"
getrandom = { version = "0.2", features = ["std"] }
byteorder = "1"
```
**Invariant:** keep `panic = "unwind"` (NOT abort) for the Android profile — abort defeats every `catch_unwind`. Keep `opt-level="z"` + LTO. DoH3 is `#[cfg(feature="doh3")]` so the base `.so` carries no quinn/h3.

## Module layout — `torta_core/src/`
```
lib.rs        # EXISTS — add `mod resolver;` + 4 nativeResolver* JNI exports (firewalled)
dns.rs        # EXISTS — wire codec. GROWS validate_response() + answer-record parser
blocklist.rs  # EXISTS — matcher; resolver consults it BEFORE any socket
resolver/
  mod.rs        # OnceLock<Resolver>: rt + TransportPool + cache + cfg + YeAH state. configure/resolve/stats/shutdown
  transport.rs  # trait Transport { async fn exchange(&self, query_wire:&[u8]) -> Result<Vec<u8>,E> }
  doh.rs        # Http2Doh  — hyper + hyper-rustls (ring)
  doh3.rs       # Http3Doh  — quinn + h3   #[cfg(feature="doh3")]
  doq.rs        # DnsOverQuic — quinn ONLY, no h3 (RFC 9250: 2-byte len-prefixed DNS msg, one query per bidi stream, query ID=0)  #[cfg(feature="doh3")]
  dnscrypt.rs   # DnsCrypt  — hand-rolled v2: stamp, cert fetch/verify/rotate, encrypt/decrypt, relays
  cache.rs      # sharded LRU keyed (qname_lower,qtype,qclass); pos+neg TTL; epoch = blocklist fingerprint
  pool.rs       # per-upstream pool, cert cache, happy-eyeballs, encrypted-only fallback ladder, YeAH cwnd
```
**Keystone — NEW `dns::validate_response(query_wire, response_wire) -> Result<(),RejectReason>`:** per-request question-match (case-insensitive qname + qtype + qclass), ID-echo guard (per-request for HTTP, not global), exact ANCOUNT walk with the same `MAX_POINTER_JUMPS=16`/`MAX_NAME_LEN=255` bounds as `read_name`. **The transport authenticates the channel; `validate_response` authenticates the answer.** Transports are dumb pipes for opaque wire bytes.

## JNI + Kotlin + datapath seam
4 firewalled exports (each `catch_unwind(AssertUnwindSafe)` like `nativeBlocklist*`):
- `nativeResolverConfigure(specsJson, timeoutMs, cacheCap) -> jstring` → `"ready=N transports=…"` | null
- `nativeResolverResolve(query: JByteArray) -> jbyteArray` → response | null (null ⇒ Kotlin falls through)
- `nativeResolverStats() -> jstring` (JSON) · `nativeResolverShutdown()`

`resolver::resolve` = sync façade doing `rt.block_on(pool.resolve(q))` with `tokio::time::timeout`. **Async panic firewall (non-negotiable):** every spawned task body in its OWN `catch_unwind(AssertUnwindSafe)` → task panic = SERVFAIL + counter, never abort. Kotlin `TortaCore` adds crash-proof façades mirroring `compileBlocklist`/`isBlocked`.

`resolve()` order (in-process, single pass): **block-check (`blocklist::query`→`build_nxdomain_response`, no egress) → cache → encrypted transport → `validate_response` → return.** Blocking is now cheaper than today (no upstream round-trip).

**Datapath seam (real path: app UDP/53 → tun ServiceVPN → native C tunnel `jni/invizible/{dns,udp,ip}.c` → loopback dnscrypt-proxy → reply → `ServiceVPN.dnsResolved`):**
- **Stage 0 SHADOW** (2b–2d, zero risk): in `ServiceVPN.dnsResolved()` (~line 350, beside `BlocklistRuntime.observe`), new `ResolverRuntime.shadowCompare(rr)` fires the same query into Rust on IO dispatcher, compares answer + latency-Δ into MonokumaDnsEngine metrics. Never touches the user's real answer.
- **Stage 1 PRIMARY behind flag** `RESOLVER_NATIVE_ENABLED` (default off): new C-ABI `torta_resolve(ptr,len,out,cap)->isize` in `jni/invizible/udp.c`(+`dns.c`) at the UDP/53 forward point calls `resolver::resolve` directly (no JNIEnv). Non-null within deadline ⇒ inject reply; null/timeout ⇒ **fall through** to dnscrypt-proxy (datapath twin of the panic firewall).
- **Stage 2 REPLACE** (2e): flip default on, stop spawning the Go binary, fall-through shrinks to a system-DNS bootstrap used only for the DNSCrypt cert fetch.

**Config = swappable upstream set (P10 rotation seam):** `nativeResolverConfigure` takes JSON `{upstreams:[{id,transport,url|stamp,bootstrap,weight}]}`; P10 re-calls `configure` → atomic pool swap. CAKE/YeAH governs selection: per-upstream RTT/loss via stats; the YeAH cwnd that paced 6 probes/5s now paces in-flight real queries (concurrency cap = cwnd) per upstream. Lifecycle mirrors `MonokumaDnsEngineManager` (`onDnsCryptStarted` → configure; standalone stop → reconfigure to public DoH/DoH3; else shutdown).

## Threat list (the Perfect-Review core) — `validate_response` is the anti-poisoning keystone
**Response integrity:** T1 TXID mismatch (per-request, ID=0 ok for HTTP) · T2 question mismatch (Kaminsky — byte-equal qname+qtype+qclass; highest-value check) · T3 off-path Do53 (N/A: encrypted-only is an INVARIANT not a knob) · T4 out-of-bailiwick glue (consume only Answer for the asked name; never cache Additional) · T5 ANCOUNT lying (walk exactly ANCOUNT, bounded; shortfall ⇒ SERVFAIL).
**Malformed/exhaustion:** T6 64 KiB body cap (capped streaming read) · T7 decompression-bomb names (reuse dns.rs caps in the answer parser) · T8 EDNS0 buffer 1232 · T9 TC bit ⇒ SERVFAIL never silent Do53 · T10 in-flight cap ≈256 + per-query timeout + bounded LRU.
**Transport/TLS/crypto:** T11 FORBID `danger_accept_invalid_certs` (CI grep fails on `accept_invalid`/`dangerous(`); `rustls-platform-verifier` needs `android::init_with_env(&env,context)` BEFORE any TLS · T12 no leaf pinning (rotation bricks); system-trust + hostname; Expert-only SPKI pin · T13 ladder encrypted-only DoH3→DoH2→DNSCrypt→fail-closed SERVFAIL (never plaintext) · T14 DNSCrypt cert: Ed25519-verify vs stamp pk, enforce ts_start/ts_end, highest valid es_version, refresh before expiry · T15 CSPRNG client nonce, never reused; AEAD tag = integrity.
**QUIC:** T16 `enable_early_data=false` (0-RTT replay) · T17 amplification (we're client; body cap + timeout) · T18/T22 rotate connection IDs, no pin across Wi-Fi↔cellular (pooled-but-rotated) · T19 UDP/443 blocked ⇒ fast degrade to DoH2, never cleartext.
**Privacy (a security property):** T20 NO qname in logs at default verbosity ever (CI lint) · T21 RFC 8467 padding to 128B multiples · T23 anonymized DNSCrypt relays (different operators), staged last.
**Panic-firewall/FFI for async:** T24 every spawned task body `catch_unwind` ⇒ SERVFAIL+counter; verify profile not `panic=abort`; tested with a deliberate `panic!()` per wave · T25 tun thread blocks only on bounded `block_on(timeoutMs)` · T26 idempotent shutdown drops runtime+sockets; emulator `/proc/<pid>/fd` leak-check across 10× stop/start.

## Per-sub-wave build + emulator checks
- **2b DoH (START):** Http2Doh + rustls/ring + platform-verifier `android::init_with_env` + `dns::validate_response` + answer parser + per-task catch_unwind + 64KiB cap + timeout + no-qname-log + EDNS padding; runs shadow. Closes T1,T2,T5,T6,T11,T20,T24,T25,T26. **Emulator:** FINGERPRINT on x86_64; shadow agrees with dnscrypt-proxy; mismatched-question ⇒ rejected no crash; forced `panic!()` ⇒ SERVFAIL app stays up; expired/bad cert ⇒ refused; 10× ServiceVPN restart ⇒ fd stable.
- **2c DoH3:** Http3Doh (quinn+h3, gated); **#1 gotcha: the QUIC UDP fd must be `VpnService.protect()`-ed** or egress loops into our tun (recommend: create in Rust, expose fd via JNI for Kotlin to protect); 0-RTT off; keepalive off/long (battery); conn-ID rotation; fast DoH3→DoH2 fallback. Closes T13,T16,T17,T18,T19. **Emulator:** DoH3 shadow agrees; 0-RTT refused; block UDP/443 ⇒ fast fall-through, **pcap shows zero plaintext :53**; protected-fd verified; panic+leak repeats.
- **2d DNSCrypt v2:** parse sdns:// → cert fetch (TXT) → Ed25519 verify vs stamp pk + validity window + highest es_version → X25519 shared secret (cache per cert) → frame `<client-magic><client-pk><nonce><AEAD(padded query)>` → UDP (TCP on TC) → decrypt + nonce-echo check + strip padding; CSPRNG nonce; relay scaffold (0x81). Closes T14,T15,T21. **Emulator:** shadow vs real public resolver agrees; **expired + wrong-signature certs both rejected**; 1000 queries ⇒ 1000 distinct nonces; tampered byte ⇒ AEAD fail ⇒ dropped no crash.
- **2e PRIMARY + retire dnscrypt-proxy** (only after 2b/2c/2d shadowed at volume, ZERO disagreements + ZERO crashes): flip default; real `build_nxdomain_response` enforcement; encrypted-only ladder live; anonymized relays; bounded LRU (never cache failure as success; epoch = blocklist fingerprint); pooled-but-rotated; Expert toggles; decommission Go binary (one-version rollback). **Emulator:** browsing session loads + blocked NXDOMAIN'd; **full egress pcap ⇒ ZERO plaintext :53** (the single most important system test); kill-all-upstreams ⇒ fails CLOSED; multi-hour soak ⇒ RSS+FD flat; relay test ⇒ resolver-facing IP is the relay not the device.

## Risks to flag before implementation
1. DNSCrypt cert rotation + anonymized relays break in the field (clock skew, es-version/AEAD mismatch, relay-operator overlap). **Don't delete the Go binary until the 2d shadow diff is clean for DAYS, not minutes.**
2. `rustls-platform-verifier` is NOT zero-config — Kotlin shim + `android::init_with_env(JNIEnv/Context)` before any TLS, or all DoH/DoH3 TLS hard-fails (DNSCrypt unaffected, no X.509).
3. DoH3 protected-fd crosses the Rust↔Kotlin boundary — recommend create-in-Rust, expose fd via JNI for Kotlin to protect.
4. `h3`/`h3-quinn` pre-1.0 — pin EXACT in Cargo.lock; feature-gated so churn never blocks 2b/2d.
5. Confirm no panic escapes the tokio runtime internals on the pinned version — the per-wave panic-injection emulator test is the empirical guard.
6. `reqwest`/`hickory` rejected by design — re-adding is a re-litigation (drags aws-lc-rs + a full resolver), not a silent add.
7. Cache correctness is a security surface — key on **validated** `(qname,qtype,qclass)` only, clamp TTLs, never store failure as success. Fix the keying contract in 2b's `validate_response`.
