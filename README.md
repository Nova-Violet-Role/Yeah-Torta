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
[![All Contributors](https://img.shields.io/badge/all_contributors-3-9b59b6.svg?style=flat-square)](#-contributors)

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

**🎯 Mission** — Give people a privacy tool that can *show its work*: every protection backed by evidence they can read for themselves, and every limitation stated as plainly as every strength.

**🌟 Vision** — A world where "this app protects you" is a claim with an instrument behind it, not a marketing line — and where saying *"this part is not proven yet"* is normal engineering rather than an embarrassment.

Built by [Nova-Violet Role](https://github.com/Nova-Violet-Role), a non-profit working at the intersection of law, code and cognitive science. Everything we make is open, free, and meant to be taken apart.

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

## 🎮 Tired of high ping and lag?

**Then you already know the feeling.** You are in the middle of a ranked match. Someone else in the house starts a download, your phone decides *now* is a great time to sync photos, and suddenly your character is teleporting. Your connection speed did not change. Your **queue** did.

That is called **bufferbloat**, and it is the single most common cause of "my internet is fast but my game lags". A fat download fills every buffer between your phone and the world, and your game's tiny, urgent packets get stuck in the queue behind it — like an ambulance behind a parade.

**Tortä's answer is a congestion brain called 🐺 BEAST**, and it has three parts with silly names and serious jobs:

| name | what it really is | what it does for you |
|:--|:--|:--|
| 🍜 **Yeah TCP/UDP** | the congestion algorithm (`beast/yeah.rs`) | learns how much your connection can *actually* take, in real time — and unlike classic TCP algorithms, it treats **UDP round-trips as first-class evidence**. Most of your gaming traffic is UDP, so this is the part that stops the engine from being blind to exactly the traffic you care about |
| 🍡 **Mochi-Dango** | the escalation valve (`beast/scheduler.rs`) | when things go wrong repeatedly, it does not panic — it escalates *gradually*, in a streak, so a moment of bad Wi-Fi does not make the engine overreact and make everything worse |
| 🧁 **Soft-cake** | the queue law, an AQM (`beast/scheduler.rs`) | sorts your traffic into three tins and makes sure the urgent one is never buried |

### The three tins — this is the whole trick

Every connection your phone makes gets sorted by where it is going (`forwarder/shape.rs`):

| tin | what lands there | how it is treated |
|:--|:--|:--|
| 🔴 **CRITICAL** | DNS — ports 53 / 853 | **floor-protected.** It cannot be starved, ever. This is your phone's ability to *find* servers at all |
| 🟡 **HIGH** | interactive — 443 / 80 / 22 | **runs unshaped, latency first.** Page loads and API calls are never paced |
| ⚪ **NORMAL** | everything else, bulk | **paced.** Big TCP transfers get a write budget (1–16 segments per burst) so they fill the pipe *without* filling the queue |

The result in one sentence: **the download still gets your full speed, but it stops parking on top of everything else.**

**Now the honest detail, because the flattering version was wrong.** A first draft of this section claimed your game's UDP is "never paced". It is not true, and the source says so: a game on a high UDP port lands in the NORMAL tin and goes through the paced path like any other bulk flow (`forwarder/run.rs:186-195`). Here is what actually protects you, which is better than the marketing line anyway:

- **The budget is a ceiling, not a brake.** A game sends small, frequent bursts — nowhere near the 1–16 segment budget. Pacing only *binds* on flows genuinely trying to fill the pipe. Your match traffic passes through untouched; the download is the one that meets the ceiling.
- **A paced flow is never killed.** On loss the window backs off toward a minimum and the flow **lives** — because a truly dead path and a briefly bad one look identical for a moment, and killing the second one is how "optimisers" ruin games.
- **The engine refuses to guess.** It only records a round-trip when exactly one request was outstanding when the answer arrived. Pipelined traffic gets pacing but contributes **no** timing sample, rather than a fabricated one (`run.rs:351-353`). An engine that invents measurements tunes itself into a hole.

### The other three things that help, and why

1. **Fewer requests, full stop.** Mobile games are stuffed with ad and analytics endpoints. Every one is a DNS lookup, a TLS handshake and a burst of traffic *while you play*. Tortä denies them before the connection exists (🛡️ WARDEN), so they never compete with your game at all.
2. **Faster "finding" of things.** Matchmaking, login, asset servers and CDN downloads all start with a DNS lookup. Tortä caches aggressively, keeps upstreams warm, and rolls back any upstream that goes quiet (🔄 ROTATION) — so the lookup that starts your match is not the one that times out.
3. **Assets served from your own phone.** Game sites and launchers pull the same handful of CDN libraries over and over. 🌌 CENTAURI serves them locally after the first fetch — zero network round-trip, zero queue.

### 🧬 The part that is genuinely unusual — and no kernel was harmed

Congestion control normally lives in **the kernel**, it normally governs **TCP**, and changing it normally requires **root** — a custom ROM, a `sysctl`, a module. That is why "fix your bufferbloat" advice always ends with *"…so flash a new router firmware"*.

Tortä does it **in userspace, on a stock phone, with no root and no kernel modification whatsoever.** Nothing is patched, nothing is loaded, no `su` is ever invoked for this. The engine sits on the VPN interface Android already gives every app, and does the queue management there — which means it works on a locked bootloader, on a carrier-branded phone, on a device you cannot unlock.

Three things make that combination rare enough to name:

| | |
|:--|:--|
| **UDP is a first-class citizen** | classic congestion control learns from TCP acknowledgements. Ours takes real round-trips from **UDP transactions** as primary evidence (`beast/mod.rs:637`) — and only when exactly one request was outstanding, so it never learns from a guess. Most of what you care about — games, QUIC, DNS — is UDP, and it is normally invisible to this kind of tuning |
| **Bufferbloat control without a speed cap** | the usual home fix is to *throttle* — cap yourself at 80% of your line so queues stay empty. Tortä does not cap anything. The window **grows to whatever the path will carry** and only paces the burst pattern, so you keep your full throughput and lose the queue |
| **No root, no kernel, no ROM** | it runs where any VPN app runs |

> **How to phrase this honestly:** we have not found another Android application doing userspace UDP congestion control with priority queueing and no root, and we would genuinely like to know if one exists — open an issue and we will credit it here. What we will **not** write is "the world's first", because that is a claim about every piece of software ever written, and nobody can check it. *"We know of no other"* is the strongest version we can actually stand behind.

### 🚫 What it does **not** do — read this part

We would rather lose the sale than lie to you:

- **It cannot beat physics.** If the game server is 8,000 km away, your base ping is set by the speed of light and Tortä cannot argue with it. Nothing can.
- **It is not a "gaming VPN".** It does not reroute you through a faster path or a closer region. It manages *your own queue*, on *your own device*.
- **It will not fix a bad Wi-Fi signal**, a congested tower, or an ISP that is oversubscribed at 9pm.
- **The tin behaviour is MEASURED, not PROVED.** The no-starvation and fairness results come from the engine's own simulator (`beast/beastsim.rs`, 6 scenario tests) and 102 further tests in `beast/tests.rs` — including a deliberate negative control that fails the suite if the NORMAL tin is ever starved to zero. That is strong evidence. It is **not** the same as a Lean theorem, and it is **not** yet a measurement taken during a real match on a real device. When that measurement exists, it will appear here with the numbers.

> **The honest summary:** Tortä will not lower your ping to the server. It removes the *self-inflicted* lag — the lag your own device creates by letting a download, an ad tracker and a photo sync trample your game. For most people on a busy home network, that is the lag they actually feel.

---

## 🏛️ The pillars at a glance — what each one does *for you*

The long version is above. This is the version you can read in thirty seconds.

| pillar | what it does | what you notice | how you can check |
|:--|:--|:--|:--|
| 🛡️ **WARDEN** | decides whether a connection may exist at all | apps that phone home simply cannot | `REJECT` rows in `cache/query.log` |
| 🌌 **CENTAURI** | serves common CDN files from your own phone | pages using jQuery & friends load with no network trip | the serve counters on the dashboard |
| 🎭 **MASKSOLVER** | tries transports until one honestly answers | lookups still work when one upstream sulks | `query-masksolver.log` names the rung that answered |
| 🐺 **BEAST** | tunes windows, pacing and queues live | downloads stop strangling everything else | the live tin depths in the UI |
| 🔄 **ROTATION** | changes upstream so no one operator sees it all | nothing — and that is the point | it **rolls back** if the new upstream goes quiet |
| 🍰 **WIRE CAKE INU** | gets extra capability without root, reversibly | features that normally need root, working | it tells you exactly what it gained |
| 🔐 **DNSCRYPT** | encrypts the lookups themselves | your network operator stops reading your DNS | PQ and classic exchanges are counted apart |
| ⛓️ **UNDERGROUND LAYER** | the deny plane, with five distinct gates | ads and trackers die before connecting | every denial is labelled with *which* gate did it |
| 🌐 **NETSTACK FORWARDER** | the userspace TCP/UDP datapath | everything above actually reaching your traffic | it is the road the other eight drive on |

---

## 💡 Tips & tricks

**Start here, in this order.** Turning everything on at once is the fastest way to have a bad time and not know which pillar caused it.

1. **Run it plain for a day.** DNSCrypt on, everything else default. If your phone is happy, you have a baseline — and a baseline is the thing that makes every later problem diagnosable.
2. **Then read your own ledger.** `cache/query.log` is one tab-separated row per decision. It is the single most useful thing in the app, and almost nobody looks at it. You will find out which app on your phone is the chattiest, and the answer is usually a surprise.
3. **Turn on the deny plane next**, before Centauri. It is the pillar with the biggest visible payoff and the smallest risk.
4. **Leave Centauri for last**, and only if you want it. It mints a certificate authority; that is a real trade and it is explained in [SECURITY.md](SECURITY.md).

**Small things worth knowing:**

- 🕵️ **If a site breaks, the ledger tells you why in one line.** Look for the most recent `REJECT` row for that domain — the label names the exact gate. No guessing, no bisecting settings.
- 📵 **A browser with its own DoH will make Tortä look broken.** It is not: the browser stopped asking. Brave, Chrome and Firefox all do this. Tortä sinkholes the bootstrap endpoints for exactly this reason — but if you have manually pinned a secure DNS provider in your browser settings, turn it **off** and let the engine do it.
- 🎮 **Before a match, do nothing.** Seriously. The best thing you can do is *not* start a big download; the queue law helps, but the physics of a saturated uplink still exist.
- 🔋 **The engine is not a battery hog, but the screen is.** If you leave the dashboard open watching the counters move, that is your battery — not the resolver.
- 🧊 **Rotation is boring on purpose.** If you never notice it happening, it is working. The interesting part is the rollback, and you can see it in the log when an upstream stops answering.

**Funny, but true:**

- 😅 This project once shipped a build where the whole CDN pillar was **silently missing** because of a single missing `--features mirror` flag. Everything was green. Every counter was zero. The fix was one word; finding it took a day. There is now a gate in CI whose entire job is to grep the built library for four symbols, because of that one day.
- 🕳️ We also once made the cloak work *perfectly* — it intercepted exactly what it was supposed to — and the browser returned `ERR_CONNECTION_TIMED_OUT` on everything, because there was nothing on the other end. A feature being **on** made the internet stop. That is why the cloak now refuses to arm unless it can prove it is able to answer.
- 🎩 Three certificate authorities once shared the same name and the same filename, and the trust check happily accepted all of them. It was matching on the *name*. It now matches on the actual bytes, and there are 12 Lean theorems making sure it stays that way.
- 📛 The app module is called `libumdnscrypt`, the engine is `torta_core`, the CDN is named after a **star system**, and the congestion algorithm is named after **rice cakes**. We regret nothing.

> Every story above is in [NOTICE.md](NOTICE.md), in a table, with the instrument that caught it. A project that only tells you its wins is selling you something.

---

## 🥮 What's in a name? (everything here is cake)

Nothing in this project is named at random. It is all the same joke, carried further than anyone should carry a joke.

### 🏛️ `libum` — the ancient Roman cake, and why the app module is called `libumdnscrypt`

**Libum** *(neuter noun, Latin)* — a **sacrificial cake** offered to the household gods. Not a metaphor: a real recipe, written down by **Cato the Elder** in *De Agri Cultura* (§75, ~160 BC), and one of the oldest surviving in Europe:

> Two pounds of cheese, well crushed. One pound of wheat flour. One egg. Mix into a single mass, shape it into a loaf, lay it on **bay leaves**, and bake it slowly under a hot crock.

A Roman household baked one, offered it at the hearth, and *then* everyone ate it. It was an offering **and** dinner. That is precisely what a DNS engine is: something you set at the threshold of the house, quietly, so that everything which comes in has been dealt with — and which you then enjoy without thinking about it.

So `libumdnscrypt` is the **cake laid at the door**. The module that sits at the boundary of the device and handles what tries to cross it.

### 🍰 …and the rest of the bakery

| name | what it means | what it is |
|:--|:--|:--|
| **Tortä** | *torta* — cake, in Latin's descendants (Italian, Spanish, Portuguese) with a German umlaut for the accent | the whole engine |
| **libum** | the Roman offering-cake, Cato's recipe | the Android module, at the threshold |
| **Soft-cake** | a cake that yields under pressure without breaking | the queue law — it gives way gracefully instead of collapsing |
| **Mochi-Dango** | 🍡 pounded rice cakes on a skewer, one after another | the escalation valve — a **streak**, each step a little firmer than the last |
| **Yeah** | YeAH-TCP, a real published congestion algorithm — and, conveniently, a thing you shout | the congestion brain. The classic loss law is the paper's (`yeah.rs:31` cites §3); the **LineRate** rung on top, which makes UDP round-trips first-class, is this project's own |
| **WIRE CAKE INU** | 🐕 the cake that comes with a dog attached | the privilege pillar — it fetches |
| **Centauri** | Alpha Centauri, the nearest star system | the CDN — because the closest source wins |
| **BEAST** | it is a beast | it is a beast |

### 🔪 And yes — `lib.rs` really is slices of *libum*

This is the Socio's joke and it is too accurate to leave out. In Rust, **`lib.rs` is the crate root** — the single file that decides what the outside world can see. Everything the Android app is allowed to touch passes through it.

So the engine is a *libum*, and `lib.rs` is where it gets **sliced**: 7,659 lines whose job is to cut the cake into portions and hand them across the boundary, one `#[uniffi::export]` at a time. **181 slices**, counted — `centauri_serve_hits`, `mirror_status`, `beast_set_yeah_profile` and 178 others. If a capability is not sliced there, the app simply cannot have any, no matter what the engine can do internally.

And the plate it is served on is **[Slint](https://slint.dev)**: the entire interface is compiled Rust, so the UI is not a separate app *describing* the engine — it is the same cake, plated. **Slices of libum, served on Slint.** 🍰

*(For the record: nobody has tried Cato's recipe with two pounds of cheese. If you do, the results belong in an issue.)*

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

## ✨ Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="33.33%">
        <a href="https://github.com/Saimonokuma">
          <img src="https://avatars.githubusercontent.com/u/Saimonokuma?v=4" width="100px;" alt="Saimonokuma"/><br />
          <sub><b>Saimonokuma</b></sub>
        </a><br />
        <a href="#code" title="Code">💻</a>
        <a href="#doc" title="Documentation">📖</a>
        <a href="#design" title="Design">🎨</a>
        <a href="#infra" title="Infrastructure">🚇</a>
        <a href="#test" title="Tests">⚠️</a>
        <a href="#maintenance" title="Maintenance">🚧</a>
      </td>
      <td align="center" valign="top" width="33.33%">
        <a href="https://github.com/jedisct1">
          <img src="https://avatars.githubusercontent.com/u/124872?v=4" width="100px;" alt="Frank Denis"/><br />
          <sub><b>Frank Denis</b></sub>
        </a><br />
        <a href="#tool" title="Tools">🔧</a>
        <a href="#security" title="Security">🛡️</a>
        <a href="#research" title="Research">🔬</a><br />
        <sub><i>Keeper of the Encrypted Hearth</i></sub>
      </td>
      <td align="center" valign="top" width="33.33%">
        <a href="https://github.com/Gedsh">
          <img src="https://avatars.githubusercontent.com/u/Gedsh?v=4" width="100px;" alt="Garmatin Oleksandr"/><br />
          <sub><b>Garmatin Oleksandr</b></sub>
        </a><br />
        <a href="#code" title="Code">💻</a>
        <a href="#infra" title="Infrastructure">🚇</a><br />
        <sub><i>InviZible Pro — the origin</i></sub>
      </td>
    </tr>
  </tbody>
</table>
<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

This table follows the [all-contributors](https://allcontributors.org) specification, which exists precisely because **GitHub's Contributors sidebar counts commit authorship and nothing else** — so it structurally cannot show someone whose contribution is a protocol, a signing tool, or the codebase this one grew out of.

> **Why we did not simply add them to that sidebar.** It can be done — a `Co-authored-by:` trailer on any commit puts a name in the graph. We did not, because it would assert that Frank Denis and Garmatin Oleksandr co-wrote commits they have never seen. Credit that misstates what someone did is not a favour to them. The contribution is real and it is recorded here, where it is accurate: the counts below are from `git grep` on this tree, and anyone can check them.

---

## 🏅 Acknowledgements

### 🔐 [@jedisct1](https://github.com/jedisct1) — Frank Denis — **Keeper of the Encrypted Hearth**

An honorary title, and a deliberate one — for the author of **DNSCrypt**, **minisign** and **libsodium**, three projects this repository stands on. DNSCrypt is pillar 7 in its entirety; minisign is what lets Centauri trust a byte before serving it. Two of the nine pillars rest on his work.

 In the Roman house the *libum* — the cake this project's Android module is named for — was baked and offered at the **hearth**, the threshold where whatever enters the home is dealt with first. **DNSCrypt is that threshold here:** the pillar that encrypts the lookups themselves, so the questions your device asks stop being legible to whoever is carrying them.

His name is written into the head of [`dnscrypt_section.slint`](rust/torta_ui/ui/dnscrypt_section.slint) — **inside the interface**, not in a credits file nobody opens. Which makes the wordplay complete: the engine is a *libum*, `lib.rs` slices it, Slint plates it, and now he is in the slices too. 🍰

**Thank you.** The DNSCrypt surface is better for your involvement.

And to **[InviZible Pro](https://github.com/Gedsh/InviZible)**, which this began as a fork of — the foundation everything above was built on.

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

<!-- TAGS:BEGIN generated from .github/tags.txt -- do not hand-edit -->
<sub>

**#dns-over-https** · **#private-dns** · **#dns** · **#dns-privacy** · **#dnscrypt** · **#doh** · **#android** · **#rust** · **#kotlin** · **#slint** · **#adblock** · **#blocklist** · **#dns-server** · **#privacy** · **#cdn** · **#formal-verification** · **#lean4** · **#vpn** · **#no-root** · **#uniffi** · **#dns-resolver** · **#android-app** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#homograph** · **#rebind** · **#warden** · **#local-cdn** · **#content-addressed** · **#dns-filtering** · **#network-security** · **#vpn-service** · **#tun** · **#post-quantum** · **#open-source** · **#agpl** · **#eupl** · **#alpha** · **#pre-release**

*Tags are generated from [`.github/tags.txt`](.github/tags.txt) by the Meta Hashtag Manager — every one names something present in this tree.*

</sub>
<!-- TAGS:END -->
