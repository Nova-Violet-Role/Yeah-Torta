# Yeah! Tortä — where everything is and what it does

Every number here was **measured** on 2026-08-01 (`git ls-files`, `wc -l`, `cargo`, `adb`), not
remembered. Where a figure is a snapshot it says so. If a number here disagrees with the tree,
the tree is right and this file is stale — re-measure with the commands shown.

---

## The one-line flow

```
rust/  --(cargo-ndk)-->  libumdnscrypt/src/main/jniLibs/<abi>/libtorta_core.so
                              |
                              +--(gradle assemble)-->  libumdnscrypt-universal-alpha.apk
                                                              |
                                                              +--(adb install)-->  the phone/AVD
```

`rust/` is the **engine**. `libumdnscrypt/` is the **app**. Everything else is support.

---

## Top level

| folder | what it is | tracked files |
|---|---|---|
| **`rust/`** | the engine — all Rust | 2020 |
| **`libumdnscrypt/`** | the Android app — Kotlin, Slint activity, manifest, the packaged `.so` | 445 |
| `uniffi-rs-main/` | **vendored** uniffi toolchain (the bindings generator). Not our code | 1167 |
| `.codemap/` | generated index, refreshes itself on commit | 519 |
| `fastlane/` | store metadata / screenshots | 232 |
| `tools/` | `avd-guard.ps1` and the AVD hazard notes | 8 |
| `included_licenses/`, `LICENSES/` | licence texts — **never delete** | 9 |
| `.avd-guard/` | **not tracked, not code**: `emulator.pid` + `beat`. The AVD guard's lock and heartbeat so two emulators never race | 0 |

Build entry points: `gradlew` / `gradlew.bat`, `settings.gradle`, `build.gradle`.

---

## `rust/` — the engine

| crate | lines | linked into the app? |
|---|---|---|
| **`torta_core`** | the bulk of 172k Rust lines | **YES** — this is the `.so` |
| **`torta_ui`** | `src/lib.rs` ≈ 7k + 38 `.slint` files (20,191 lines) | **YES** — all the graphics |
| **`carbon_bridge`** | 3,020 | **YES** — `torta_ui/Cargo.toml:48`; used at `torta_ui/src/lib.rs:6821` (`route::SocketProbe`), `:6883` (`surface::CarbonSurface`), `:6895` (`sandbox::FsJail`), `:6925` (`engine::parse_document`) |
| **`torta_iconforge`** | `lib.rs` 200 + `main.rs` 372 + 3 `.slint` | **NO — by design.** It is a HOST tool |

### `torta_core` — the core

The most complicated folder, and the one where the DNS actually happens.

```
src/
  lib.rs              the UniFFI surface — every function Kotlin can call
  resolver/           THE DATAPATH
    mod.rs              resolve_inner: block-check -> DoH sinkhole -> Warden -> cache -> transport
    doh_bypass.rs       client-DoH bootstrap sinkhole (added 2026-08-01)
    pool.rs, routing.rs, transport.rs, do53.rs, doh.rs, odoh.rs, dnscrypt.rs
    cache.rs, rebind.rs, never_forward.rs, dns64.rs, local.rs, log.rs
  warden/             the firewall — 9,751 lines. mod.rs 4,557, object.rs 2,461, tracker.rs 894
  beast/              congestion control — 7,785 lines
                        tests.rs 2478 | scheduler.rs 1392 | mod.rs 1225 | yeah.rs 978
                        linksim.rs 530 | beastsim.rs 505 | spec_binding.rs 416 | log.rs 261
  forwarder/          the netstack — 3,603 lines
                        run.rs 917 | mod.rs 566 | shape.rs 539 | icmp.rs 506 | sni.rs 439
                        upstream.rs 387 | tun_device.rs 134 | session.rs 115
  blocklist.rs, underground.rs, mirror/ (Centauri store), tunnel/, egress.rs, runtime_tier.rs
```

**Neither `beast/` nor `forwarder/` contains a single `allow(dead_code)`.** Measured suppression
census (app crates only, excludes vendored): `allow(dead_code)` = **26 in 16 files**; any
`allow(...)` = **76 in 23**. Across all tracked `.rs` including vendored: **168 in 57**.

### `torta_iconforge` — the render forge AND its own verdict

Not just the launcher icon. Two commands in `main.rs`:

* `render` — one-shot render of a scene/variant, `--frame <t>` sets the animation clock
* `forge-anim` — bakes an animation loop to `frame_000.png…` (sprite sheets; the cake breathes)

`lib.rs` is the **GOLDEN-DIFF CORE**: a pure verdict over pixel bytes — `is_blank` (one flat colour
is never a render), `size_mismatch`, `differing_pixels` with `max_delta`. It exists because the
crate once shipped an EMPTY `lib.rs`, so its green build proved nothing.

It has **no `[lib]` section** in `Cargo.toml` and declares its **own `[workspace]`**, which is why
nothing links it — that is deliberate, not a defect. It is the instrument that can prove a Slint
pane rendered instead of coming out blank.

---

## `libumdnscrypt/` — the app

```
src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/
  slint/        TortaSlintActivity, TortaSlintBridge, TortaPillarBridge  <- UI <-> engine
  rust/         TortaCore.kt          the ONE façade over the .so; never throws
  dns_engine/   ResolverRuntime (arms every resolver flag), RotationManager (2 brains + 3 gates),
                BlocklistSearcher, PillarLog, QueryLogTailer, solver/, beast/, wire_cake_inu/
  modules/      ServiceVPN, ModulesService, ModulesKiller — the Android service layer
uniffi/torta_core/torta_core.kt   GENERATED (26,889 lines). Never hand-edit
src/main/jniLibs/<abi>/           where the engine .so is packaged from
src/test/                         unit tests (JVM). src/test/resources/routing/ holds the 100-URL corpus
```

**Regenerating bindings** (needed whenever a `#[uniffi::export]` is added):

```bash
cargo build --lib --features mirror                      # HOST cdylib
uniffi-bindgen generate --library D:/cargo-targets/torta/debug/torta_core.dll \
    --language kotlin --out-dir libumdnscrypt/src/main/kotlin
```

> **Trap, measured:** uniffi library mode against a **cross-compiled Android `.so`** produces
> **nothing** and still **exits 0**. It must read the HOST cdylib. Two runs looked green and wrote
> no file.

---

## The nine pillars, and where each one lives

| pillar | engine | app |
|---|---|---|
| WARDEN | `warden/` | `WardenDatapathGate`, warden dashboard |
| CENTAURI | `mirror/` (content-addressed store, `#[cfg(feature = "mirror")]`) | Centauri tiles |
| MASKSOLVER | `resolver/` + `query-masksolver.log` | solver/ |
| BEAST | `beast/` | `beast/BeastTuneBrain.kt` |
| ROTATION | pool/routing | `RotationManager.kt` |
| WIRE CAKE INU | — | `wire_cake_inu/` (self-ADB elevation, `PowerCatalogue.kt`) |
| DNSCRYPT | `resolver/dnscrypt.rs` | `ResolverRuntime` |
| UNDERGROUND LAYER | `underground.rs` | licences |
| NETSTACK FORWARDER | `forwarder/` | `ServiceVPN` |

---

## Build & test commands that are known to work

```bash
# engine (Rust changed -> the .so is NOT optional)
cd rust/torta_core
cargo test --lib --features mirror                       # 1307 tests
ANDROID_NDK_HOME=D:/android-sdk/ndk/23.1.7779620 \
  cargo ndk -t x86_64 -o ../../libumdnscrypt/src/main/jniLibs build --release --features mirror

# app
./gradlew :libumdnscrypt:compileUniversalDebugKotlin
./gradlew :libumdnscrypt:testUniversalDebugUnitTest --tests "*SomeTest*"
./gradlew :libumdnscrypt:assembleUniversalDebug
#   -> libumdnscrypt/build/outputs/apk/universal/debug/libumdnscrypt-universal-alpha.apk

# device — ALWAYS stop, uninstall, reinstall
adb shell am force-stop app.torta.yeah && adb uninstall app.torta.yeah && adb install -r <apk>
```

> **`--features mirror` is not optional.** A build without it produces a `.so` with **zero**
> `mirror_status` symbols and silently regresses Centauri's HTTPS serve leg. Verify with
> `grep -ac mirror_status <so>` — old and new must match.
>
> The variant is `universalDebug`, not `debug`: `compileDebugKotlin` is **ambiguous** and fails.

---

## Proof instruments (where the truth comes from)

| instrument | what it settles |
|---|---|
| `cargo test --lib --features mirror` | the engine's logic, 1307 tests |
| `gradlew test…UnitTest` | the app's pure decision helpers |
| **Lean 4** in `D:/Lean/proofs/Proofs/` | universal claims: `RotationAnsweringGate.lean`, `DenyAttribution.lean`, `CacheTtlClamp.lean` |
| `lake env leanchecker <Module>` | the kernel re-verifying the proof terms (exit 0 + zero bytes) |
| `run-as app.torta.yeah cat cache/query.log` | **the ledger** — the honest per-query record |
| `logs/query-<pillar>.log` | per-pillar events (`rotation switch`, `rollback`, …) |
| `torta_iconforge` golden-diff | a Slint pane RENDERED and is not blank |

The ledger format is TAB-separated:
`[ts] \t client \t qname \t TYPE \t VERDICT \t Nms \t source \t -`

A denial names the gate that made it — `blocklist`, `warden`, `underground`, `homograph`,
`doh-bypass`. Those five labels are **proved injective** in `DenyAttribution.lean`, so a denial
can never be misattributed.

---

## Hazards that cost real time (each learned once, the hard way)

* **Never read a build's exit code through a pipe.** `cmd | tail` gives you `tail`'s status.
* On-device `grep` over a uiautomator XML **segfaults** — pull the file to the host first.
* `adb push` with `MSYS_NO_PATHCONV=1` breaks host `/tmp` paths — use a real Windows path.
* `screencap` needs `</dev/null` and `-p`.
* `brave://` URLs cannot be opened by an external intent.
* `am force-stop` on Brave destroys same-tab reuse.
* A page-error check that cannot fire scores 100% while measuring nothing — always drive a
  known-bad URL as a negative control.
* Mutation harness: assert the needle count **before** building. A patch that fails to apply is
  `DISCARDED`, never `SURVIVED` — they mean opposite things.

---

<sub>

**#codebase** · **#architecture** · **#codemap** · **#documentation** · **#rust** · **#kotlin** · **#slint** · **#uniffi** · **#android** · **#android-app** · **#dns** · **#dns-resolver** · **#dnscrypt** · **#doh** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#cdn** · **#local-cdn** · **#content-addressed** · **#blocklist** · **#adblock** · **#dns-filtering** · **#homograph** · **#rebind** · **#warden** · **#tun** · **#forwarder** · **#congestion-control** · **#no-root** · **#privacy** · **#lean4** · **#formal-verification** · **#nova-violet-role** · **#yeah-torta** · **#alpha**

*Tag source of truth: [`.github/tags.txt`](.github/tags.txt) — every tag names something present in this tree.*

</sub>
