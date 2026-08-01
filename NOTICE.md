<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2 -->
<!-- Copyright 2026 Saimonokuma. -->

<div align="center">

# 📋 NOTICE

**Attribution, third-party licences, and the defect record**

*Yeah! Tortä · Nova-Violet Role*

</div>

---

## 🙏 Attribution

**Yeah! Tortä** began as a fork of **[InviZible Pro](https://github.com/Gedsh/InviZible)**
© Garmatin Oleksandr, licensed AGPL-3.0. The Android service layer, the VPN plumbing and
much of the app scaffolding descend from that work, and the project is grateful for it.

What was added since: a Rust engine (`rust/torta_core`), an interface compiled from Rust
via Slint (`rust/torta_ui`), a content-addressed local CDN, a UniFFI bridge, and a Lean 4
proof layer.

## 🏅 Honorary contributors

Some people shape a project without ever appearing in `git log`. This section exists so the
record is complete rather than merely accurate.

### 🔐 [@jedisct1](https://github.com/jedisct1) — Frank Denis — **Keeper of the Encrypted Hearth**

The title is chosen for a reason rather than for the sound of it. In the Roman house the
*libum* — the cake this project's Android module is named after — was baked and offered at
the **hearth**: the threshold where whatever enters the home is dealt with first.

**DNSCrypt is that threshold, and he built it.**

This is not a courtesy credit. Three of his projects are load-bearing here, and the counts
are measured from the tracked tree:

| his work | what it does for Tortä | present in |
|:--|:--|:--|
| **[DNSCrypt](https://dnscrypt.info/) / [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy)** | the encrypted DNS protocol and the proxy this project's whole DNSCRYPT pillar is built around | **77 files** |
| **[minisign](https://jedisct1.github.io/minisign/)** | signature verification for Centauri's catalogue — the reason the offline CDN can trust a byte before serving it | **50 files** |
| **[libsodium](https://libsodium.org/)** | the cryptographic floor underneath the above | **4 files** |

Without DNSCrypt there is no pillar 7. Without minisign, Centauri has no way to know a
catalogue is genuine, and the entire content-addressed design collapses into "download
something and hope". Two of the nine pillars stand on his work.

His name is written into the head of
[`rust/torta_ui/ui/dnscrypt_section.slint`](rust/torta_ui/ui/dnscrypt_section.slint) —
**inside the interface itself**, on the surface that configures his protocol, not in a
credits file nobody opens.

### 🦀 And the part he might actually find interesting: the client is Rust, in-process

The engine does not shell out to a proxy. **DNSCrypt is implemented natively inside
`torta_core`** — 7,002 lines across three modules, called directly by the resolution ladder
at [`resolver/mod.rs:1165`](rust/torta_core/src/resolver/mod.rs):

| | measured |
|:--|:--|
| `resolver/dnscrypt.rs` | 4,042 lines — the client: certificates, nonces, padding, the exchange |
| `resolver/dnscrypt_config.rs` | 2,046 lines — the typed config, authoritative over the TOML |
| `resolver/dnscrypt_update.rs` | 914 lines — resolver-list refresh |
| primitives on that path | X25519 · XSalsa20 · XChaCha20 · Ed25519 · Poly1305 · Curve25519 |
| certificate / nonce / magic handling | 568 references — cert rotation is real, not stubbed |
| **Anonymized DNSCrypt** | relay chains supported (`set_relays`, `parse_relay_chain`) |
| **post-quantum** | `set_pq_enabled` — PQ and classic exchanges are counted **separately**, because a counter that merges them cannot tell you which one you actually got |

**A correction to an earlier version of this file, which understated the truth.** It said the
Go `dnscrypt-proxy` was "still bundled". That was wrong, and counting settled it:

| measured on the tracked tree | count |
|:--|--:|
| `.go` source files | **0** |
| `dnscrypt-proxy` executables anywhere on disk | **0** |
| tracked `jniLibs/` files (how Android ships Go binaries) | **0** |

**There is no Go implementation in this project.** The engine's DNSCrypt is the only DNSCrypt.

What *is* bundled is `assets/dnscrypt.zip` — **36 text files, 236 KB, no executable** — and it
is not an implementation, it is a **data directory**: your minisign-signed resolver catalogue
(`public-resolvers.md` + `.minisig`, `relays.md` + `.minisig`, the ODoH lists), a stock TOML,
and a set of rule files most of which are empty placeholders.

And those signed lists are **load-bearing for the Rust path**: `ResolverRuntime.kt:811,878,907`
derives the live DNSCrypt lane from `server_names ∩ the signed public-resolvers.md stamps`.
Shipping them is what lets the app resolve on first launch without the bootstrap deadlock of
needing DNS in order to fetch a list of DNS servers.

So the accurate sentence is: **the Go proxy is gone; the signed catalogue it used stayed,
because it is yours and it is good.** The open work is smaller than previously stated — drop
the empty rule stubs and stop naming a data bundle after a program that is no longer here.

**Thank you, Frank.** The protocol is the reason this pillar exists at all, and minisign is
the reason another one can be trusted. The hearth is the right place to be remembered.

---

## 📦 Third-party components

| component | licence | where |
|:--|:--|:--|
| InviZible Pro (upstream) | AGPL-3.0 | app scaffolding, service layer |
| UniFFI (Mozilla) | MPL-2.0 / Apache-2.0 | `uniffi-rs-main/` (vendored) |
| Slint | GPL-3.0 / commercial / royalty-free | the UI toolkit |
| Carbonyl | see `rust/carbon_bridge/LICENSE.carbonyl.md` | `carbon_bridge` |
| Rust crate dependencies | per-crate, mostly MIT/Apache-2.0 | `Cargo.toml` files |
| Android/AndroidX libraries | Apache-2.0 | `build.gradle` |

Full texts live in [`LICENSES/`](LICENSES/) and [`included_licenses/`](included_licenses/).
This project is itself dual-licensed **AGPL-3.0-or-later OR EUPL-1.2**, at your option.

---

## 🔍 The defect record

This section exists because a project that only publishes its successes is advertising.
Every entry below was found **by measurement, against our own work**, and written down
rather than quietly fixed. They are kept public because each one is a class of mistake
another project can make.

| # | what looked fine | what was actually true | how it was found |
|:--|:--|:--|:--|
| 1 | a green release build | the `.so` carried **zero** `mirror_status` symbols against an expected 4 — a whole pillar silently disabled | `grep -ac` on the built library, comparing old and new |
| 2 | a fully-rendered browser page, all pillars green | **zero** ledger rows — the browser had resolved its own DoH endpoint once and tunnelled everything, blinding all nine pillars at once | reading `cache/query.log` and finding it empty |
| 3 | a cloak that fired correctly (`sinkholes 0 → 11`) | the browser got `ERR_CONNECTION_TIMED_OUT` — interception with nothing behind it, a black hole caused by a feature being *armed* | driving a real asset on a real device |
| 4 | "is the CDN serving?" answered with a counter | the counter (`cloak_actions`) measures blocklist sinkholes and **can never move** for that pillar | reading the counter's definition instead of its value |
| 5 | a health check that passed | it dialled `127.0.0.1`, which the browser never uses — the real path is the tun sentinel and the hairpin | `/proc/net/tcp`, then asking which address the *client* dials |
| 6 | a CA trust test that passed | it matched on **name only**; three separately-minted CAs shared a subject and an anchor filename | minting a second CA and watching the test still pass |
| 7 | a mutation suite reporting SURVIVED | the patch had never applied — `sed` escaping, and a heredoc turning `\n` into a newline | asserting the needle count *before* building |
| 8 | a green `lake build` | one theorem was **contingent**: it froze today's constants as if they were invariants, and went red on a correct change | the change itself |
| 9 | three README numbers | 28 vs 25 theorems, 5 vs 13, 24,038 vs 24,223 lines | re-counting from source before the first push |

**None of these were caught by a test suite going red.** Every one needed someone to ask
*which instrument said that* — which is why the question is written into the
[Code of Conduct](CODE_OF_CONDUCT.md) as a normal, friendly thing to ask.

---

## 🧭 Standing commitments

1. **A false green is a defect**, and it is in scope for [security reports](SECURITY.md).
2. **Unproven claims stay labelled unproven**, including on the front page.
3. **Instruments must be able to fail** — a check that has never rejected anything is an
   untested alarm, and gets a negative control before it is trusted.
4. **When the spec and the code disagree**, they move in the same commit, and the new value
   is justified from first principles rather than from what makes the check pass.

---

<div align="center">

### 🍰 Yeah! Tortä

*Nine pillars. One ledger. No claim without an instrument.*

© 2026 Nova-Violet Role · Non-Profit Organization

*Created with ❤️ for the advancement of human understanding*

</div>

---

<!-- TAGS:BEGIN generated from .github/tags.txt -- do not hand-edit -->
<sub>

**#attribution** · **#license-compliance** · **#third-party** · **#dns** · **#dns-privacy** · **#dnscrypt** · **#doh** · **#android** · **#rust** · **#kotlin** · **#slint** · **#adblock** · **#blocklist** · **#dns-server** · **#privacy** · **#cdn** · **#formal-verification** · **#lean4** · **#vpn** · **#no-root** · **#uniffi** · **#dns-resolver** · **#android-app** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#homograph** · **#rebind** · **#warden** · **#local-cdn** · **#content-addressed** · **#dns-filtering** · **#network-security** · **#vpn-service** · **#tun** · **#post-quantum** · **#open-source** · **#agpl** · **#eupl** · **#alpha** · **#pre-release**

*Tags are generated from [`.github/tags.txt`](.github/tags.txt) by the Meta Hashtag Manager — every one names something present in this tree.*

</sub>
<!-- TAGS:END -->
