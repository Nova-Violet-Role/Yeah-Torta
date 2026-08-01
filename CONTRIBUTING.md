<!-- SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2 -->
<!-- Copyright 2026 Saimonokuma. -->

<div align="center">

# 🤝 Contributing to Yeah! Tortä

**Every lens is welcome here**

*Nova-Violet Role · Non-Profit Organization*

[![Ko-fi](https://img.shields.io/badge/Support-Ko--fi-FF5E5B?style=for-the-badge&logo=ko-fi&logoColor=white)](https://ko-fi.com/saimonokuma)
[![Community Driven](https://img.shields.io/badge/Community-Driven-764ba2?style=for-the-badge)](https://github.com/Nova-Violet-Role)

</div>

---

## 👋 Start here

Thank you for being here. This is a non-profit project, which means the only thing
anyone is paid in is usefulness — and there is a lot of it to go around.

**You do not need to know Rust, Kotlin, Lean 4 and DNS to help.** Almost nobody does.
Pick the lens you already have:

| Area | How you can help |
|:--|:--|
| 💻 **Code** | engine transports, Android lifecycle, forwarder correctness |
| 🎨 **Design** | the interface is Slint — components, icons, animations |
| 📐 **Proofs** | extend the Lean 4 layer, especially the pillars that have none yet |
| 🧪 **Testing** | run it on real hardware and tell us what broke, with the log rows |
| 📖 **Documentation** | if something confused you, that is a bug in the docs |
| 💡 **Ideas** | tell us what a DNS engine should be able to prove about itself |

Reporting *"I tried this and it did not work"* — with what you ran and what you saw —
is a real contribution. It is often a better one than a patch.

---

## 🎯 The one rule

**No claim without a green run.** Paste the command and its real exit code. Not
"this should work" — the output.

This is not a hazing ritual, it is the whole reason the project exists. Things here
have looked green while being badly broken, more than once, and the habit of showing
the output is what catches it.

Read the exit code **directly, never through a pipe.** `./gradlew assemble | tail`
gives you `tail`'s status, not Gradle's. That has produced a false green in this
project before.

## What you need

| tool | why |
|:--|:--|
| JDK 17 | the Android build |
| Rust (stable) + `cargo-ndk` | the engine and the UI are Rust |
| Android SDK + NDK | cross-compiling the `.so` |
| Node 20 | the A14 uniffi-record guard is a Node script |

No binary is committed. The `.so` files, the UniFFI Kotlin bindings and the APKs
are **build output** — you produce them, and so does CI. That is deliberate: a
repository that ships prebuilt artifacts cannot prove it still knows how to make
them.

## Building

```bash
# 1. the engine — --features mirror is NOT optional
cd rust/torta_core
cargo ndk -t x86_64 -o ../../libumdnscrypt/src/main/jniLibs build --release --features mirror

# 2. the UI (Slint compiles during this step)
cd ../torta_ui
cargo ndk -t x86_64 -o ../../libumdnscrypt/src/main/jniLibs build --release

# 3. the APK
cd ../..
./gradlew :libumdnscrypt:assembleUniversalDebug
```

Flavours are `arm64`, `armv7a`, `universal` (x86_64). The task is
`assembleUniversalDebug`, **not** `assembleDebug` — the latter is ambiguous and fails.

> **`--features mirror` is load-bearing.** A build without it succeeds, produces a
> `.so` with **zero** `mirror_status` symbols, and silently disables Centauri while
> every other signal stays green. Verify before you trust it:
> `grep -ac mirror_status libumdnscrypt/src/main/jniLibs/<abi>/libtorta_core.so`

## Changing the UniFFI surface

If you add or change a `#[uniffi::export]`, regenerate the bindings **from the host
cdylib**:

```bash
cd rust/torta_core
cargo build --lib --features mirror
cargo run --bin uniffi-bindgen --features uniffi-cli -- \
  generate --library target/debug/libtorta_core.so \
  --language kotlin --out-dir ../../libumdnscrypt/src/main/kotlin
```

> **Measured trap:** pointing `--library` at a cross-compiled **Android** `.so`
> makes `uniffi-bindgen` exit **0** and write **nothing**. Two runs looked green
> and produced no file. CI's `bindings-drift` job exists because of this.

Never hand-edit `uniffi/torta_core/torta_core.kt`. It is generated.

## Before you open a PR

```bash
cd rust/torta_core && cargo test --lib --features mirror   # 1311 tests
cd ../.. && ./gradlew :libumdnscrypt:testUniversalDebugUnitTest
./gradlew :libumdnscrypt:assembleUniversalDebug
```

CI runs all of it plus the bindings-drift diff and the symbol assertion. A PR that
is red in CI will not merge, including a Dependabot one.

## What a good PR looks like here

1. **State the instrument.** Which command, which output, which exit code. A claim
   with no named instrument is unverified — mark it so yourself.
2. **Add the alarm with the feature.** If you add a guarantee, add the thing that
   would catch it failing. A test that cannot fail spends someone's trust.
3. **Try to break it before you claim it.** Mutate your own change — drop a
   conjunct, flip a constant — and check the test actually goes red. If nothing
   kills it, say so and label it infrastructure rather than a guarantee.
4. **Say plainly what you weakened.** If a fix required loosening a check,
   changing a constant, or narrowing a claim, put that in the first sentence.
5. **Move the spec with the code.** If you change an emitted shape or a constant,
   the guard and its corpus move in the *same* commit — and justify the new value
   from first principles, never from what makes the check pass.

## Formal proofs

Some invariants are proved in Lean 4 rather than sampled — 84 machine-checked
theorems, zero `sorry`, every one mutation-tested. They live in a **separate Lean
workspace**, not in this repository, and are cited by name in `README.md`. If you
extend them, the closing ritual is three instruments: `lake build` (exit code read
directly) → `#print axioms` (a `sorryAx` means not proved) → `leanchecker` (an
independent kernel re-verification).

## Device testing

Some claims only a real device can settle — DNS interception, the cloak, the deny
ledger. CI cannot answer those. When your change touches the datapath, include the
`cache/query.log` rows and a **control**: a row that was *not* affected, proving the
instrument was capable of showing a difference.

Always **force-stop → uninstall → reinstall** when you rebuild the `.so`. An
upgrade install can keep the old native library and you will measure the previous
build.

## 📄 Licensing

Dual AGPL-3.0-or-later OR EUPL-1.2. New source files carry the SPDX header block —
copy it from any neighbouring file. By contributing you agree your work ships under
both.

---

## 💬 If you get stuck

Open an issue and say where you got to. A half-finished attempt with the error
attached is genuinely welcome — someone will meet you there, and the question you
were embarrassed to ask is usually the one three other people also had.

Please also read the [Code of Conduct](CODE_OF_CONDUCT.md). It is short, and it is
kinder than most.

---

<div align="center">

### 🍰 Yeah! Tortä

*Nine pillars. One ledger. No claim without an instrument.*

[![Support Our Journey](https://img.shields.io/badge/🔗_Support_Our_Journey-Ko--fi-FF5E5B?style=for-the-badge)](https://ko-fi.com/saimonokuma)

© 2026 Nova-Violet Role · Non-Profit Organization

*Created with ❤️ for the advancement of human understanding*

</div>

---

<!-- TAGS:BEGIN generated from .github/tags.txt -- do not hand-edit -->
<sub>

**#contributing** · **#good-first-issue** · **#build-from-source** · **#github-actions** · **#ci** · **#cargo-ndk** · **#gradle** · **#android-ndk** · **#mutation-testing** · **#dns** · **#dns-privacy** · **#dnscrypt** · **#doh** · **#android** · **#rust** · **#kotlin** · **#slint** · **#adblock** · **#blocklist** · **#dns-server** · **#privacy** · **#cdn** · **#formal-verification** · **#lean4** · **#vpn** · **#no-root** · **#uniffi** · **#dns-resolver** · **#android-app** · **#odoh** · **#dnssec** · **#dns64** · **#svcb** · **#homograph** · **#rebind** · **#warden** · **#local-cdn** · **#content-addressed** · **#dns-filtering** · **#network-security** · **#vpn-service** · **#tun** · **#post-quantum** · **#open-source** · **#agpl** · **#eupl** · **#alpha** · **#pre-release**

*Tags are generated from [`.github/tags.txt`](.github/tags.txt) by the Meta Hashtag Manager — every one names something present in this tree.*

</sub>
<!-- TAGS:END -->
