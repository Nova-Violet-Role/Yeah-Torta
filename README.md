<div align="center">

# 🍰 Yeah! Tortä

**A DNS engine that tells you the truth about itself**

*Nine pillars, one Rust core, and a rule: no claim ships without an instrument that could have failed*

[![Ko-fi](https://img.shields.io/badge/Support-Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/saimonokuma)
[![Nova-Violet Role](https://img.shields.io/badge/Nova--Violet-Role-9b59b6?style=for-the-badge)](https://github.com/Nova-Violet-Role)
[![Pre-Release](https://img.shields.io/badge/status-ALPHA_·_PRE--RELEASE-e67e22?style=for-the-badge)](#-status-this-is-an-alpha)
[![License](https://img.shields.io/badge/License-AGPL--3.0_OR_EUPL--1.2-764ba2?style=for-the-badge)](#-license)

[![Rust](https://img.shields.io/badge/Rust-engine-000000?style=flat-square&logo=rust&logoColor=white)](rust/)
[![Kotlin](https://img.shields.io/badge/Kotlin-app-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](libumdnscrypt/)
[![Slint](https://img.shields.io/badge/Slint-UI-2379F4?style=flat-square)](rust/torta_ui/)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](#-building)
[![Proved in Lean 4](https://img.shields.io/badge/Proved%20in-Lean%204-2C3E50?style=flat-square)](#-what-is-proved-not-merely-tested)
[![Tests](https://img.shields.io/badge/engine%20tests-1311%20passing-27ae60?style=flat-square)](#-instruments)

</div>

---

## 📜 About

Most privacy tools on Android tell you they are working. A switch turns green, a card says *protected*, a counter goes up. Almost none of them can tell you **whether a single query was actually answered the way the card claims** — and the gap between "armed" and "working" is where privacy software quietly fails.

**Yeah! Tortä** is an Android DNS engine built around the opposite instinct. Every pillar has to produce evidence a user can read: a ledger row, a counter that moves, a resolved address you can `ping`. When a pillar cannot prove it is working, it is designed to **go dark rather than look green** — because a feature that silently drops your connections is worse than a feature that is off.

- 🦀 **Rust core** — resolver, forwarder, blocklist, mirror, warden. `#[cfg]`-gated, no root required.
- 🎨 **Slint UI** — the whole interface is compiled Rust, not XML layouts.
- 📐 **Lean 4 proofs** — the invariants that must hold for *every* input are machine-checked, not sampled.
- 📓 **A ledger you can read** — `cache/query.log`, one tab-separated row per decision, with the gate that made it.

It began as a fork of [InviZible Pro](https://github.com/Gedsh/InviZible) (AGPL-3.0) and has grown a Rust engine, a Slint interface, a content-addressed local CDN and a formal-methods layer around it.

---

## 🚧 Status: this is an ALPHA

The APK is literally named `libumdnscrypt-universal-alpha.apk`, and that is not decoration. **This is a pre-release.** Some pillars are proven on a device, some are proven only in tests, and at least one is knowingly incomplete. That distinction is tracked in public rather than smoothed over:

| claim | instrument | state |
|:--|:--|:--|
| Client-DoH bootstrap is sinkholed | `cache/query.log` rows `… A REJECT 0ms doh-bypass` on a device, with a passing control (`github.com` resolves) | ✅ **proven on device** |
| Rotation never lands on a mute upstream | `RotationAnsweringGate.lean`, 14 theorems + on-device rollback | ✅ **proven** |
| Cloak never intercepts what it cannot serve | `CloakServable.lean` (25 theorems), `live_gate_is_sound` | ✅ **proven** |
| A stale CA with the same name cannot pass as ours | `CloakTrustIdentity.lean` (12 theorems), device negative control | ✅ **proven** |
| Centauri **serves** a cloaked asset end to end | serve ledger `centauri_serve_hits` | ❌ **NOT proven** — the hairpin leg is silent; the cloak is deliberately dark until it answers |

That last row is the honest state of the newest pillar, and it is in the README on purpose. A project that only publishes its green rows is not reporting, it is advertising.

---

## 🏛️ The nine pillars

Each pillar is a distinct guarantee with its own code, its own counters and its own failure mode.

### 1. 🛡️ WARDEN — the datapath gate
`rust/torta_core/src/warden/` · 9,751 lines

The last thing between a packet and the network. Warden holds numbered rules (`block_dns_bypass`, hardcoded-resolver denial, port policy) and decides whether a *connection* — not just a name — is allowed to exist. It is the pillar that catches an app trying to talk to `8.8.8.8:53` directly, having never asked us to resolve anything.

### 2. 🌌 CENTAURI — the offline CDN
`rust/torta_core/src/mirror/` · 24,223 lines · `#[cfg(feature = "mirror")]`

A Decentraleyes/LocalCDN idea taken further: a **content-addressed, signature-verified local mirror**. Common CDN assets (jQuery and friends) are fetched **at most once**, hash-verified against a minisign-signed catalog, and served from a loopback server afterwards. The upstream CDN sees one request ever, instead of one per site you visit.

It is guarded by a four-conjunct gate — TLS trust **and** something servable **and** a watched host **and** that exact host in the servable set — because an interception that cannot serve is a black hole, not a privacy win. That gate is proven in Lean (`CloakServable.lean`), and the *reason* it needs all four conjuncts is written into the source as an incident report.

### 3. 🎭 MASKSOLVER — the resolution ladder
`rust/torta_core/src/resolver/` · `query-masksolver.log`

Escalates a query through transports until something honest answers: cache → local records → DNSCrypt → DoH → plain, with retry budgets, negative caching, TTL floors and ceilings, and serve-stale. Every rung records *why* it moved to the next one, so a slow answer can be attributed instead of guessed at.

### 4. 🐺 BEAST — the adaptive tuner
`rust/torta_core/src/beast/` · 7,785 lines

Watches live behaviour (latency, loss, cache hit rate) and tunes the engine's own knobs — window, in-flight cap, pacing. The interesting engineering is the anti-thrash work: hysteresis and invariants that stop a tuner from oscillating between two equally bad states, which is the classic way self-tuning systems make things worse.

### 5. 🔄 ROTATION — the upstream carousel
`RotationManager.kt` + engine pool/routing

Rotates DNS upstreams on a schedule so no single operator sees your whole history. The load-bearing part is the **health gate**: after switching, it sends real labelled queries (`torta-rotverify-<entropy>.example.com`) and **rolls back** if the new upstream does not *answer*. Reachable is not answering — that lesson is now formalised in `RotationAnsweringGate.lean`, and it recurs across the codebase.

### 6. 🍰 WIRE CAKE INU — privileged capability, without root
`libumdnscrypt/src/main/kotlin/.../wire_cake_inu/`

Self-ADB elevation and a catalogue of what that unlocks (`PowerCatalogue.kt`). Where a capability genuinely needs more privilege than an app has, this pillar acquires it explicitly and reversibly, and reports what it gained — rather than pretending the feature works without it.

### 7. 🔐 DNSCRYPT — encrypted transport
`rust/torta_core/src/resolver/dnscrypt.rs` + `ResolverRuntime.kt`

DNSCrypt v2 and DoH, with post-quantum-capable exchanges counted separately from classic ones (`pq_exchanges` / `classic_exchanges`) so you can see what you are actually getting, not what was negotiated in theory.

### 8. 🕳️ UNDERGROUND LAYER — the deny plane
`rust/torta_core/src/resolver/underground.rs`

Blocklists, homograph detection, rebind protection and the DoH-bypass sinkhole. Every denial is attributed to exactly one of five labels — `blocklist`, `warden`, `underground`, `homograph`, `doh-bypass` — and that labelling is **proved injective** in `DenyAttribution.lean`, so two different gates can never be confused in the ledger.

> The `doh-bypass` label exists because of a measurement that invalidated everything else: a fully-rendered browser page produced **zero** ledger rows. The browser had resolved its own DoH endpoint once and tunnelled every subsequent lookup to Cloudflare, blinding all nine pillars at once. Sinkholing the bootstrap apexes is what restored visibility — the ledger now shows `brave.cloudflare-dns.com … REJECT … doh-bypass`.

### 9. 🌐 NETSTACK FORWARDER — the tun datapath
`rust/torta_core/src/forwarder/` · 3,603 lines

The userspace network stack behind the VPN interface: TCP/UDP forwarding, SNI inspection, and the hairpin that lets a cloaked CDN host reach the local mirror. No root, no kernel module.

---

## 🗺️ Codemap — what this repository is made of

Measured with `git ls-files` on the published tree, **2,437 files / 615,494 lines**:

| type | files | lines | share of lines | what it is |
|:--|--:|--:|--:|:--|
| `.json` | 504 | 220,333 | 35.8% | fixtures, catalogs, blocklist corpora |
| `.rs` | 552 | 172,765 | 28.1% | the engine + vendored UniFFI |
| `.kt` | 420 | 99,901 | 16.2% | the Android app |
| `.slint` | 38 | 20,191 | 3.3% | the entire user interface |
| `.py` `.swift` `.rb` | 275 | 20,247 | 3.3% | vendored UniFFI bindings generators |
| `.kts` `.toml` `.txt` `.udl` | 483 | 12,165 | 2.0% | build + interface definitions |
| other | 165 | 69,892 | 11.4% | resources, licences, assets |

**Excluding the vendored `uniffi-rs-main/` subtree (1,026 files), the project itself is:** 140 `.rs` files / 116,424 lines, 376 `.kt` / 96,797 lines, 38 `.slint` / 20,191 lines.

Build output is **not** tracked. Before the first public push this repository carried 1,816 files and 1.6 GB of compiler artifacts (149 `.rlib`, 512 `.o`, a 90 MB `.pdb`) against 32.5 MB of actual project — which also made it unpushable, since GitHub rejects any push above 2 GB.

---

## 🧱 Architecture

```
       ┌──────────────────────────────────────────────┐
       │  Slint UI  (rust/torta_ui + .slint)          │  ← the whole interface is compiled Rust
       └───────────────┬──────────────────────────────┘
                       │  TortaSlintBridge / TortaPillarBridge
       ┌───────────────┴──────────────────────────────┐
       │  Android app  (libumdnscrypt/, Kotlin, Dagger) │  ← services, prefs, lifecycle, VPN
       └───────────────┬──────────────────────────────┘
                       │  UniFFI  (generated torta_core.kt — never hand-edited)
       ┌───────────────┴──────────────────────────────┐
       │  Rust engine  (rust/torta_core)              │
       │  resolver/ · forwarder/ · warden/ · beast/   │
       │  mirror/ · blocklist · underground           │
       └──────────────────────────────────────────────┘
```

**Four Rust crates:**

| crate | role |
|:--|:--|
| `torta_core` | the engine. Everything above happens here. |
| `torta_ui` | the Slint interface, compiled to its own `.so` |
| `carbon_bridge` | linked by `torta_ui` (see `torta_ui/Cargo.toml`) |
| `torta_iconforge` | the render-forge for icons and animations — and a **golden-diff core** (`is_blank`, `DiffVerdict`, `differing_pixels`) that exists because the crate once shipped an empty `lib.rs`, which made its green build meaningless |

---

## 🔨 Building

Requires the Android NDK, a Rust toolchain with the Android target, and JDK 17.

```bash
# 1. the engine  (--features mirror is MANDATORY: without it the Centauri
#    symbols vanish and the pillar silently regresses to inert)
cd rust/torta_core
ANDROID_NDK_HOME=/path/to/ndk cargo ndk -t x86_64 -o ../../libumdnscrypt/src/main/jniLibs \
    build --release --features mirror

# verify the symbols actually landed — a build that "succeeded" is not enough
grep -ac mirror_status ../../libumdnscrypt/src/main/jniLibs/x86_64/libtorta_core.so   # expect 4

# 2. the bindings, IF the UniFFI surface changed
#    NOTE: --library must point at the HOST cdylib. Given a cross-compiled
#    Android .so, uniffi-bindgen exits 0 and writes NOTHING.
uniffi-bindgen generate --library target/debug/torta_core.dll \
    --language kotlin --out-dir ../../libumdnscrypt/src/main/kotlin

# 3. the APK
cd ../..
./gradlew :libumdnscrypt:assembleUniversalDebug
```

Gradle variants are flavoured — `:libumdnscrypt:assembleUniversalDebug`, not `assembleDebug`.

---

## 📐 What is proved, not merely tested

Some properties must hold for **every** input, not for the inputs a test happens to supply. Those are proved in **Lean 4** — machine-checked, zero `sorry`, and every theorem re-verified by `leanchecker` (an independent kernel pass over the compiled proof terms, which answers *is this proof valid* rather than *did elaboration finish*).

```lean
-- a stale certificate with our exact name is NOT us
theorem identity_test_refuses_the_stale_certificate : ¬ trustedByIdentity measured1 measured3

-- the cloak can never intercept a host it cannot serve
theorem live_gate_is_sound (h : cloakFires g) : g.inServableSet ∧ g.tlsTrusted

-- five deny gates, five labels, no two confusable
theorem fixed_labelling_is_injective : Function.Injective fixedLabel
```

| module | subject | theorems |
|:--|:--|--:|
| `RotationAnsweringGate.lean` | rotation rolls back unless the new upstream *answers* | 14 |
| `CloakServable.lean` | CLOAK ⊆ SERVABLE — never intercept what you cannot serve | 25 |
| `CloakTrustIdentity.lean` | a name is not an identity; a same-CN CA is not ours | 12 |
| `DenyAttribution.lean` | deny labelling is injective and total over the gates | 13 |
| `CacheTtlClamp.lean` | TTL floor/ceiling clamping is idempotent and in-range | 20 |

**Every theorem is mutation-tested.** A theorem no mutation can kill is decorative, so each proof is deliberately broken — a conjunct dropped, a constant swapped — and must go red. Mutations that fail to *apply* are reported as **discarded**, never as survived; the two mean opposite things, and conflating them is how a proof suite lies in the reassuring direction.

The proofs live in a separate Lean 4 + mathlib workspace and are not part of the Gradle build.

---

## 🔬 Instruments

Nothing here is claimed on the strength of reading the code.

| instrument | question it answers |
|:--|:--|
| `cargo test --lib --features mirror` | **1,311 passing** — do the engine's units behave? |
| `cache/query.log` | one TSV row per decision: `[ts] client qname TYPE VERDICT Nms gate` |
| `centauri_serve_hits` / `_bytes` / `_misses` / `_unauthorized` | did the offline CDN actually serve bytes, or only intercept? |
| `centauri_cloak_sinkholes` | how many lookups the cloak redirected — read **next to** the serve count |
| `adb shell ping <host>` | the ground truth for a cloak or a sinkhole, with a control host |
| `lake build` → `#print axioms` → `leanchecker` | elaboration, then what it rests on, then an independent kernel re-check |

A counter that cannot move is not an instrument. The serve ledger above exists because the metric previously reached for (`cloak_actions`) counts blocklist sinkholes and **can never move for Centauri at all** — the dashboard read "LIVE — serving" on the strength of a number that measures something else.

---

## 🤝 Contributing

This is a pre-release and the surface is moving. Pull requests are welcome, and the bar is the same one the project holds itself to:

| area | how you can help |
|:--|:--|
| 🦀 **Engine** | resolver transports, forwarder correctness, warden rules |
| 📱 **App** | Android lifecycle, Dagger graph, VPN service edge cases |
| 🎨 **UI** | Slint components, the icon/animation forge |
| 📐 **Proofs** | extend the Lean 4 layer — especially the pillars with none yet |
| 🧪 **Testing** | run it on real hardware and report what breaks, with the log rows |

**One rule above the rest:** if you add a guarantee, add the instrument that would catch it failing — and try to break it before you claim it works. A green test that cannot fail is worse than no test, because it spends someone's trust.

See [TORTA-CODEBASE.md](TORTA-CODEBASE.md) for the full tour: where every module lives, what it does, and the traps measured the hard way.

---

## 📄 License

Dual-licensed at your option under **AGPL-3.0-or-later** OR **EUPL-1.2** — see [LICENSES/](LICENSES/).

Derived from [InviZible Pro](https://github.com/Gedsh/InviZible) © Garmatin Oleksandr, AGPL-3.0. Vendored components retain their own licences (see `included_licenses/` and `rust/carbon_bridge/LICENSE.carbonyl.md`).

---

<div align="center">

### 🍰 Yeah! Tortä

*Nine pillars. One ledger. No claim without an instrument.*

[![Support Our Journey](https://img.shields.io/badge/🔗_Support_Our_Journey-Ko--fi-FF5E5B?style=for-the-badge)](https://ko-fi.com/saimonokuma)

[Releases](https://github.com/Nova-Violet-Role/Yeah-Torta/releases) · [Issues](https://github.com/Nova-Violet-Role/Yeah-Torta/issues) · [Codebase tour](TORTA-CODEBASE.md)

---

<sub>

**#dns** · **#dnscrypt** · **#doh** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#cdn** · **#local-cdn** · **#content-addressed** · **#blocklist** · **#adblock** · **#dns-filtering** · **#homograph** · **#rebind** · **#warden** · **#tun** · **#vpn-service** · **#network-security** · **#privacy** · **#dns-privacy** · **#dns-resolver** · **#no-root** · **#android** · **#android-app** · **#rust** · **#kotlin** · **#slint** · **#uniffi** · **#post-quantum** · **#lean4** · **#formal-verification** · **#open-source** · **#agpl** · **#eupl** · **#alpha** · **#pre-release**

*Every tag above names something present in this tree — the source of truth is [`.github/tags.txt`](.github/tags.txt), which records the measured file count behind each one. A tag whose evidence reaches zero gets deleted, not kept.*

</sub>

© 2026 Nova-Violet Role · Non-Profit Organization

*Created with ❤️ for the advancement of human understanding*

</div>
