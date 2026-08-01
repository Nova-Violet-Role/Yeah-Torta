<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2 -->
<!-- Copyright 2026 Saimonokuma. -->

<div align="center">

# 🦀 DNSCrypt, in Rust, in-process

**A roadmap written for [@jedisct1](https://github.com/jedisct1) — Frank Denis**

*What we did to your protocol, what we added around it, and what we have not finished*

</div>

---

## 📬 Why this document exists

You designed DNSCrypt and wrote the reference implementation. This project implements your
protocol **natively in Rust inside its own engine**, and then builds several things on top
of it that we think are genuinely new — one of which treats a DNSCrypt round-trip as a
**congestion-control signal**, which is not a use we have seen anyone make of it.

So rather than a thank-you line in a credits file, here is the whole thing: what was ported,
what each addition buys, and — in its own section — **what is still not done**, so nothing
here reads as a claim we cannot support.

Every number below is counted from the tracked tree. If one is wrong, it is a bug and we
would like the issue.

---

## 1️⃣ The port — DNSCrypt v2, no proxy, no localhost hop

**7,002 lines** across three modules, entered directly from the resolution ladder at
[`resolver/mod.rs:1165`](rust/torta_core/src/resolver/mod.rs). There is no subprocess and no
loopback listener on this path; the engine speaks DNSCrypt itself.

| module | lines | what it is |
|:--|--:|:--|
| [`resolver/dnscrypt.rs`](rust/torta_core/src/resolver/dnscrypt.rs) | 4,042 | the client: stamps, certs, the exchange |
| [`resolver/dnscrypt_config.rs`](rust/torta_core/src/resolver/dnscrypt_config.rs) | 2,046 | the typed configuration, authoritative over the TOML |
| [`resolver/dnscrypt_update.rs`](rust/torta_core/src/resolver/dnscrypt_update.rs) | 914 | resolver-list refresh |

**It is a base transport, not a feature.** DoH3 and DoQ sit behind `#[cfg(feature = …)]`;
DNSCrypt is always compiled. It is also the one transport that does not ride rustls at all
— its security is the v2 datapath, end to end.

### The datapath, as implemented

| stage | what the code does |
|:--|:--|
| **stamp** | self-contained `sdns://` decoder for protocol `0x01` → resolver address, provider name `2.dnscrypt-cert.<provider>`, provider Ed25519 key. Written by hand because the `dnsstamps` crate is **encode-only** — the dependency note is in `Cargo.toml` |
| **cert** | plaintext TXT fetch (correct: the cert is Ed25519-signed), **verified against the stamp's provider key**, `ts_start..ts_end` enforced, and the **highest** valid `es_version` selected — XChaCha20-Poly1305 (v2) over XSalsa20-Poly1305 (v1). **Never downgrades** |
| **encrypt** | X25519(client ephemeral, resolver short-term pk) → NaCl `crypto_box` shared key (HSalsa20 / HChaCha20 per es-version). Frame is `<client-magic><client-pk><client-nonce><AEAD>`. Client nonce is **CSPRNG and never reused**. Query is **RFC-8467 padded** to a 64-byte multiple before sealing |
| **send** | UDP. The TC bit drives an RFC 7766 length-prefixed TCP fallback **only on the plaintext cert-fetch path** — an encrypted reply is taken from UDP as-is, because its byte 2 is your resolver magic, not a DNS header bit *(that one cost us a bug)* |
| **receive** | verify resolver magic `r6fnvWj8` **and** the client-nonce echo, AEAD-open — a tampered byte fails the tag and is **dropped, never a crash** — then strip padding |
| **hand-off** | the plaintext answer leaves as **opaque bytes**. This transport never parses DNS; validation happens once, elsewhere, unchanged |

**Two invariants held deliberately:** there is **no plaintext query path, ever** — not as a
fallback, not on error — and **no qname is ever written to a log** from this module. The
response read is bounded at 64 KiB.

### Anonymized DNSCrypt is wired, not just parsed

`0x81` relay stamps are decoded **and used**. When a relay chain is attached, both the
encrypted query and the cert-fetch TXT are wrapped in the anonymized envelope —
`8×0xff · 0x00 0x00 · resolver IPv6-mapped address · port (BE) · payload` — and sent to the
first relay; the resolver's reply returns verbatim. Chains are parseable from stamp lists
(`parse_relay_chain`).

### Post-quantum, counted honestly

There is a PQ switch (`set_pq_enabled`), and **PQ and classic exchanges are counted
separately** (`pq_exchanges`). A single merged counter would tell a user "encrypted" while
hiding *which* exchange they actually got, and that is precisely the class of comfortable
non-answer this project exists to avoid.

---

## 2️⃣ What we added around it — and what each one buys

This is the part we think may interest you, because it uses DNSCrypt for something beyond
carrying a query.

### 🐺 A DNSCrypt round-trip is a congestion signal

The engine has a congestion controller (**BEAST**) whose LineRate brain treats a
**UDP-family DNSCrypt RTT as a first-class congestion input**
([`beast/mod.rs:333,637`](rust/torta_core/src/beast/mod.rs)) — not a metric for a dashboard,
but evidence that drives the window.

Classic congestion control learns from TCP acknowledgements. Your protocol gives us a clean,
authenticated, request/response pair over UDP with a verifiable reply — which turns out to be
an excellent RTT sample, on a transport where samples are normally unavailable.

**The honesty rule that makes it work:** a sample is only recorded when **exactly one**
request was outstanding when the answer arrived. Pipelined traffic gets paced but contributes
**no** timing sample rather than a fabricated one. An engine that invents measurements tunes
itself into a hole.

**What it buys:** the resolver stops being a passive client of the network and starts
adapting to it, using the encrypted transport itself as the sensor.

### 🎭 A ladder that records *why* it moved on

DNSCrypt is one rung of a resolution ladder — cache → local → **DNSCrypt** → DoH → plain —
and every escalation is attributed in `query-masksolver.log`. When DNSCrypt is slow, the log
says so, instead of leaving a user to guess whether their DNS is broken.

**What it buys:** a slow answer becomes diagnosable rather than mysterious.

### 🔄 Rotation that requires an *answer*, not a ping

Upstreams rotate so no single operator sees a whole history. After a switch, the engine sends
real labelled queries and **rolls back** if the new upstream does not answer. Reachable is not
answering — proven in Lean, 14 theorems, and demonstrated by an on-device rollback.

**What it buys:** rotation cannot silently strand a user on a resolver that accepts packets
and returns nothing.

### 📐 Some of it is proved, not tested

| module | theorems | what it settles |
|:--|--:|:--|
| `SdnsScheme.lean` | 7 | stamp scheme handling |
| `YeahUdpIndependence.lean` | 14 | the UDP congestion lane cannot be corrupted by the TCP lane |
| `YeahFamilySeparation.lean` | 11 | per-family RTT floors stay separated — a v4 sample cannot poison v6 |

Zero `sorry`, kernel-rechecked, and every theorem mutation-tested: we deliberately break the
model and require the theorem to go red, because a theorem no mutation can kill is decoration.

### 🌌 minisign, doing exactly what it says

Centauri — the offline CDN — verifies its catalogue with **minisign** before a single byte is
served (50 files reference it). The content-addressed design has no meaning without a
signature it can trust; that pillar rests on your work as squarely as pillar 7 does.

---

## 3️⃣ What we have **not** done

Stated plainly, because a roadmap that lists only achievements is a brochure.

| | state |
|:--|:--|
| **No independent interop test against a reference resolver** | the client works against real resolvers, but there is no automated conformance suite in CI. Until there is, correctness rests on our tests plus live use |
| **PQ is a switch, not a proof** | it is counted separately and it runs; it has no formal treatment |
| **Empty legacy rule stubs still ship** | inside `assets/dnscrypt.zip` there are zero-byte `blacklist*.txt` / `whitelist*.txt` placeholders from the proxy's data layout. Harmless, but they should go |
| **The bundle is still named after a program that is not here** | see below — the name says `dnscrypt-proxy`, the contents are a signed catalogue |
| **The whole project is an ALPHA** | pre-release, stated on the front page, with the one unproven pillar named there |

### ⚠️ A correction we owe you, because the first draft of this document was wrong

It said the Go `dnscrypt-proxy` was "still bundled" and that calling this a full Rust port
"would be false". **We counted, and it was the draft that was false** — in the direction of
understating our own work, which is the less common way to be wrong but still wrong:

| measured on the tracked tree | count |
|:--|--:|
| `.go` source files | **0** |
| `dnscrypt-proxy` executables (any ABI, any path) | **0** |
| tracked `jniLibs/` entries — how Android ships Go binaries | **0** |

**There is no Go in this repository.** `assets/dnscrypt.zip` is **36 text files, 236 KB, zero
executables**: your minisign-signed catalogue (`public-resolvers.md` + `.minisig`, `relays.md`
+ `.minisig`, the ODoH lists), a stock TOML, and rule placeholders that are mostly empty.

We are keeping the signed lists deliberately. `ResolverRuntime.kt:811,878,907` derives the live
DNSCrypt lane from `server_names ∩ the signed public-resolvers.md stamps`, so shipping them is
what avoids the bootstrap deadlock — needing working DNS in order to fetch the list of DNS
servers. Removing them to be able to say "pure Rust, zero inherited files" would make the app
worse in exchange for a slogan.

**The accurate statement: the Go proxy is gone; your signed catalogue stayed, because it is
yours and it is good.**

---

## 4️⃣ Where this is going

1. **Drop the legacy Go assets** once the resolver lists and stock config are sourced natively — the last thing keeping a second implementation in the APK.
2. **A conformance harness in CI** that runs the Rust client against reference resolvers and diffs observable behaviour, so interop stops being an assertion.
3. **More of the transport under Lean** — the certificate window (`ts_start..ts_end`) and the never-downgrade rule are both crisp, decidable properties that deserve theorems rather than tests.
4. **Publish the congestion result** — if a DNSCrypt RTT really is a good congestion signal, that is worth writing up properly with numbers, not just shipping.

---

## 🙏 In short

Your protocol is the reason pillar 7 exists, and minisign is the reason another pillar can be
trusted at all. We reimplemented DNSCrypt v2 in Rust because we wanted it *inside* the engine
rather than beside it — and then found it could do a second job nobody had asked of it.

If any of the above is wrong, or if the anonymized-relay envelope or the cert selection has a
subtlety we have missed, **please open an issue**. We would rather be corrected by you than
be confidently wrong in public.

**Thank you.** 🔐

---

<div align="center">

### 🍰 Yeah! Tortä

*Nine pillars. One ledger. No claim without an instrument.*

© 2026 Nova-Violet Role · Non-Profit Organization

</div>

---

<!-- TAGS:BEGIN generated from .github/tags.txt -- do not hand-edit -->
<!-- TAGS:END -->
