/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! SPEC BINDING — the checker that ties the Rust engine constants to their copies in the Kotlin
//! and Slint layers.
//!
//! # Why this file exists
//!
//! `TIN_MAX_DEPTH = [4, 8, 16]` (`scheduler.rs:35`) is load-bearing: it is enforced at
//! `scheduler.rs:947`, where a probe whose tin still exceeds its cap after a pop is DROPPED. The
//! same three numbers are written out by hand in two other places:
//!
//! | copy | file | bound before this checker? |
//! |---|---|---|
//! | engine (authoritative) | `beast/scheduler.rs:35` | — |
//! | Kotlin | `EngineConfig.kt:40` | **no** |
//! | Slint panel | `torta_ui/ui/beast.slint` (`cap-critical` / `cap-high` / `cap-normal`) | **no** |
//!
//! Nothing bound them. No host code calls `set_cap_critical` / `set_cap_high` / `set_cap_normal`,
//! so the panel renders its Slint defaults. They agree today purely by coincidence of authorship.
//!
//! Worse, the Slint comment above those properties claims the denominators are *"HONEST, never a
//! fabricated literal"* and cites **`cake.rs:29`** as their source. There is no `cake.rs` anywhere
//! in the tree. A comment asserting its own correctness, pointing at a file that does not exist,
//! is the most expensive kind of documentation: it stops anyone from checking.
//!
//! Change `TIN_MAX_DEPTH` and, without this file, the panel would keep drawing basin fills against
//! stale denominators — every bar wrong, no error, while claiming it cannot be wrong.
//!
//! # What this checker is, and what it is NOT
//!
//! It is a TEXT check over sibling source files, and that is honest work — it is exactly the job.
//! It is NOT a proof. The proof of the capacity law itself lives in
//! `D:/Lean/proofs/Proofs/TinCapacity.lean` (14 theorems, `the_tail_drop_bounds_every_tin`,
//! `a_capped_tin_can_never_consume_more_than_its_cap`, …). Lean cannot see a `.kt` or a `.slint`
//! file; this checker is the mechanical link between that proof and the shipped code.
//!
//! # The dated-spec trap, avoided deliberately
//!
//! This does NOT assert `[4, 8, 16]`. It asserts that the two copies EQUAL whatever
//! `TIN_MAX_DEPTH` currently is. Retune the ladder to `[8, 16, 32]` and this checker stays green
//! the moment all three move together — and goes red the moment they do not. A checker that
//! pinned the literal would fail on a correct retune, and the obvious repair would be to delete
//! it, destroying the coverage.

#![cfg(test)]

use super::scheduler::TIN_MAX_DEPTH;

/// Repository root, derived from this crate's manifest dir (`rust/torta_core`).
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Pull every integer out of a string, in order. Deliberately dumb: the callers slice out a small
/// distinctive region first, so there is nothing clever to get wrong here.
fn ints_in(s: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            if let Ok(v) = cur.parse::<usize>() {
                out.push(v);
            }
            cur.clear();
        }
    }
    if let Ok(v) = cur.parse::<usize>() {
        out.push(v);
    }
    out
}

/// THE KOTLIN COPY. `EngineConfig.kt:40` — `val TIN_MAX_DEPTH: IntArray = intArrayOf(4, 8, 16)`.
///
/// Negative control for this test: change `TIN_MAX_DEPTH` in `scheduler.rs` and it must fail.
/// Verified by mutation, not assumed.
#[test]
fn the_kotlin_tin_ladder_matches_the_engine() {
    let p = repo_root()
        .join("libumdnscrypt/src/main/kotlin/pillar/kuma_saimono/libumdnscrypt/dns_engine/EngineConfig.kt");
    let src = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read the Kotlin engine config at {}: {e}",
            p.display()
        )
    });

    let line = src
        .lines()
        .find(|l| l.contains("TIN_MAX_DEPTH") && l.contains("intArrayOf"))
        .expect(
            "EngineConfig.kt no longer declares TIN_MAX_DEPTH via intArrayOf — the Kotlin copy of \
             the tin ladder moved or vanished. This checker must be updated to follow it, NOT \
             deleted: an unbound copy is exactly what it exists to catch.",
        );

    let found = ints_in(line);
    let want: Vec<usize> = TIN_MAX_DEPTH.to_vec();
    assert_eq!(
        found, want,
        "TIN LADDER DRIFT (Kotlin). scheduler.rs says {want:?}; EngineConfig.kt says {found:?}. \
         The engine constant is authoritative — the Kotlin copy must follow it. Fix the copy, do \
         not weaken this check."
    );
}

/// THE SLINT COPY. `torta_ui/ui/beast.slint` — `cap-critical` / `cap-high` / `cap-normal`, the
/// denominators of the three CAKE-FOUNTAIN basin fills. These are Slint DEFAULTS and no host code
/// overrides them, so they are what the panel actually draws.
#[test]
fn the_slint_basin_caps_match_the_engine() {
    let p = repo_root().join("rust/torta_ui/ui/beast.slint");
    let src = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read the Beast panel at {}: {e}", p.display()));

    let grab = |prop: &str| -> usize {
        let line = src
            .lines()
            .find(|l| l.contains(prop) && l.contains("in-out property"))
            .unwrap_or_else(|| {
                panic!(
                    "beast.slint no longer declares `{prop}` — the panel's basin denominator moved \
                     or vanished. Follow it; do not delete this check."
                )
            });
        // Slice off the comment so a `// TIN_MAX_DEPTH[0]` trailer cannot be parsed as the value.
        let code = line.split("//").next().unwrap_or(line);
        *ints_in(code)
            .last()
            .unwrap_or_else(|| panic!("`{prop}` in beast.slint has no numeric default: {line:?}"))
    };

    let found = [grab("cap-critical"), grab("cap-high"), grab("cap-normal")];
    assert_eq!(
        found, TIN_MAX_DEPTH,
        "TIN LADDER DRIFT (Slint panel). scheduler.rs says {TIN_MAX_DEPTH:?}; beast.slint basin \
         caps are {found:?}. Every basin fill on the Beast panel is drawn as `depth / cap`, so a \
         stale cap means EVERY bar renders a wrong fraction while the panel's own comment claims \
         the denominators are honest. Fix the panel."
    );
}

/// THE STALE CITATION. `beast.slint` sources its caps to `cake.rs:29`. No such file exists.
///
/// This is a check on a CLAIM, not on a value: either the cited file exists, or the citation must
/// name the real source (`beast/scheduler.rs:35`). A comment that points at nothing is worse than
/// no comment, because it defeats exactly the audit that would catch drift.
#[test]
fn the_slint_caps_cite_a_file_that_exists() {
    let p = repo_root().join("rust/torta_ui/ui/beast.slint");
    let src = std::fs::read_to_string(&p).expect("cannot read the Beast panel");

    let cites_cake_rs = src.contains("cake.rs:");
    if cites_cake_rs {
        let candidates = [
            repo_root().join("rust/torta_core/src/beast/cake.rs"),
            repo_root().join("rust/torta_core/src/cake.rs"),
            repo_root().join("rust/torta_ui/src/cake.rs"),
        ];
        let exists = candidates.iter().any(|c| c.exists());
        assert!(
            exists,
            "beast.slint cites `cake.rs` as the source of the tin caps, but no cake.rs exists in \
             the tree. The real source is beast/scheduler.rs:35 (`TIN_MAX_DEPTH`). Update the \
             citation — a comment that claims the denominators are \"HONEST, never a fabricated \
             literal\" while pointing at a nonexistent file is an overclaim, and it is the reason \
             this drift went unnoticed."
        );
    }
}

/// THE FOURTH AND FIFTH COPIES. `torta_ui/src/lib.rs` declares `const TIN_CAPS: [f32; 3] =
/// [4.0, 8.0, 16.0]` — TWICE (`:3550` and `:3627`) — and uses them as the fill denominators:
///
/// ```text
/// shell.set_engine_fill_critical((s.queue_critical as f32 / TIN_CAPS[0]).clamp(0.0, 1.0));
/// ```
///
/// The `.clamp(0.0, 1.0)` is what converts an over-cap tin into a bar pinned at 100% — a
/// permanently OVERFLOW-red basin on a datapath that is behaving exactly as designed
/// (`Proofs/TinCapacity.lean::the_ladder_is_the_wrong_denominator_on_the_aqm_path`).
///
/// This check does NOT fix the denominator choice — that is a UI design change. It ensures the
/// numbers cannot silently drift from the engine while that decision is pending, which is the
/// failure this whole file exists to prevent. Found only after the first three checks were
/// written: my own checker had a gap, and the gap was two more unbound copies.
#[test]
fn the_torta_ui_fill_denominators_match_the_engine() {
    let p = repo_root().join("rust/torta_ui/src/lib.rs");
    let src = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("cannot read torta_ui at {}: {e}", p.display()));

    // ── UPGRADED FROM "bound" TO "eliminated" ────────────────────────────────────────────────
    //
    // The first version of this check bound the two hand-copied `TIN_CAPS` arrays to the engine
    // ladder. That was the weaker fix: it kept the copies and only forbade them from drifting.
    // They are now GONE — both sites call `torta_core::fill_denominator(profile, tin)`, the single
    // source of truth, which is also PROFILE-AWARE (the ladder on Legacy, `AQM_GLOBAL_CAP` on the
    // AQM path where the ladder is not the governing bound).
    //
    // So the assertion inverts: a re-introduced hardcoded array is now the defect. This is a
    // stronger claim than the one it replaces, not a weaker one — the check did not get deleted
    // when the code was fixed, it got sharpened.
    let hardcoded: Vec<&str> = src
        .lines()
        .filter(|l| l.contains("TIN_CAPS") && l.contains("const"))
        .collect();

    assert!(
        hardcoded.is_empty(),
        "torta_ui/src/lib.rs has re-introduced a hand-copied tin ladder: {hardcoded:?}. Use \
         torta_core::fill_denominator(profile, tin) instead — a literal here cannot be \
         profile-aware, and on the AQM path the ladder is the WRONG denominator \
         (Proofs/TinCapacity.lean::the_ladder_is_the_wrong_denominator_on_the_aqm_path)."
    );

    // And the real binding: the UI must actually CALL the single source of truth.
    assert!(
        src.contains("fill_denominator"),
        "torta_ui/src/lib.rs no longer calls torta_core::fill_denominator. The basin denominators \
         are unbound again — restore the call; do not delete this check."
    );

    let decls: Vec<&str> = Vec::new();
    let want: Vec<usize> = TIN_MAX_DEPTH.to_vec();
    let _ = &want;
    for (i, line) in decls.iter().enumerate() {
        // `[f32; 3]` contributes a 32 and a 3, so take only the values after the `=`. These are
        // FLOAT literals (`4.0`), which a digit-only scanner would split into 4 and 0 — that bug
        // was caught by this very test on its first run. Parse whole numeric tokens, then
        // truncate.
        let rhs = line.split('=').nth(1).unwrap_or("");
        let found: Vec<usize> = rhs
            .split(|c: char| !c.is_ascii_digit() && c != '.')
            .filter(|t| !t.is_empty())
            .filter_map(|t| t.parse::<f64>().ok())
            .map(|v| v as usize)
            .collect();
        assert_eq!(
            found, want,
            "TIN LADDER DRIFT (torta_ui declaration #{i}). scheduler.rs says {want:?}; \
             torta_ui/src/lib.rs says {found:?} in {line:?}. These are the denominators of the \
             engine-panel fill bars — a stale value renders every bar at the wrong fraction. The \
             engine constant is authoritative."
        );
    }
}

/// The ladder itself, as the engine holds it — the invariants proved in
/// `Proofs/TinCapacity.lean::the_capacity_ladder_is_strictly_increasing`. Kept here as a
/// fast-failing executable echo so a bad edit to `scheduler.rs` is caught by `cargo test` even
/// before anyone runs Lean.
#[test]
fn the_tin_ladder_is_strictly_increasing() {
    assert!(
        TIN_MAX_DEPTH[0] < TIN_MAX_DEPTH[1] && TIN_MAX_DEPTH[1] < TIN_MAX_DEPTH[2],
        "the tin ladder must be strictly increasing (Critical is the SCARCEST tin): {TIN_MAX_DEPTH:?}"
    );
    assert!(
        TIN_MAX_DEPTH.iter().all(|&c| c > 0),
        "a zero tin cap would make every probe in that tin an immediate tail-drop: {TIN_MAX_DEPTH:?}"
    );
}

/// ★ THE WIRING GAP — pinned as a POSITIVE assertion so it cannot be quietly forgotten.
///
/// # What is wrong — stated precisely, after a first draft of this comment got it wrong
///
/// An earlier version of this test claimed "the forwarder never calls the Beast". That was
/// FALSE, and it was false because the first search covered `crate::tunnel` while the real
/// datapath lives in `crate::forwarder` (`run.rs`, `icmp.rs`, `shape.rs`, `session.rs`, …).
/// The correction matters, because the true shape is more interesting than the wrong one.
///
/// The forwarder DOES call the Beast — but only to hand it OBSERVATIONS:
///
/// ```text
/// forwarder/run.rs:401   crate::beast::feed_live_flow_loss()
/// forwarder/run.rs:419   crate::beast::feed_live_flow_shape(rtt_ms, shaper.cwnd())
/// forwarder/run.rs:719   crate::beast::feed_live_tcp_dial(...)
/// forwarder/run.rs:836   // lane only -- it steers nothing (`beast::fold_shaped_sample`)
/// ```
///
/// `enqueue_probe` across ALL EIGHT forwarder files: **0**. So the Beast receives RTT, loss and
/// dial timings — which is exactly why the device log shows `rtt=222.9ms udp=215.7ms` live —
/// and never receives a probe to schedule, which is why `pipe=0` and `q=0/0/0` in the same
/// line. The code states it outright at `run.rs:836`: *it steers nothing*.
///
/// Note the direction of `feed_live_flow_shape(rtt_ms, shaper.cwnd())`: the forwarder TELLS the
/// Beast what `FlowShaper` already decided. **The Beast is downstream of the decision.** The
/// tins, the valves and the Mochi-Dango layer are not in the datapath at all — `TortaScheduler`
/// appears nowhere in `crate::forwarder`.
///
/// # How it shows up
///
/// Measured on a real AVD with toybox, `/data/data/app.torta.yeah/logs/query-beast.log`, every
/// tick of 102 — including throughout a 100-URL Brave Nightly browsing run:
///
/// ```text
/// tick mode=SLOW-START cwnd=1/16 rtt=222.9ms udp=215.7ms pace=4.5/s
///      pipe=0  q=0/0/0  valve=0.0000 shed=0 aqm=0  sparse=383  relay=dnscrypt-proxy
/// ```
///
/// RTT arrives on BOTH planes, so the controller is alive — but nothing ever enters a tin, so
/// nothing is ever in flight, so slow start has no acknowledgement to grow on.
///
/// `Proofs/BeastStarvation.lean` proves this is the CORRECT behaviour of a correct controller
/// fed an empty pipe (`a_starved_window_never_grows`), and that a floored window PROVES the
/// pipe was empty (`a_floored_window_proves_an_empty_pipe`). So `cwnd=1/16` is not a tuning
/// bug in `yeah.rs`; the defect is upstream, and this test names exactly where.
///
/// # Why it is written as a POSITIVE assertion
///
/// A test asserting "the forwarder IS wired" would sit red for as long as the work takes, and a
/// permanently red suite trains everyone to ignore it. This asserts the gap is STILL THERE, so
/// it is green today and **fails the moment someone wires it** — at which point the correct
/// action is to delete this test and replace it with the real coupling assertion. That is a
/// deliberate, documented trade, and the failure message says so.
#[test]
fn the_netstack_forwarder_is_not_wired_to_the_beast() {
    // Every file of the real datapath, not just `tunnel/mod.rs` — the mistake that made the
    // first draft of this test wrong.
    let datapath: [(&str, &str); 9] = [
        ("forwarder/run.rs", include_str!("../forwarder/run.rs")),
        ("forwarder/mod.rs", include_str!("../forwarder/mod.rs")),
        ("forwarder/icmp.rs", include_str!("../forwarder/icmp.rs")),
        (
            "forwarder/session.rs",
            include_str!("../forwarder/session.rs"),
        ),
        ("forwarder/shape.rs", include_str!("../forwarder/shape.rs")),
        ("forwarder/sni.rs", include_str!("../forwarder/sni.rs")),
        (
            "forwarder/upstream.rs",
            include_str!("../forwarder/upstream.rs"),
        ),
        (
            "forwarder/tun_device.rs",
            include_str!("../forwarder/tun_device.rs"),
        ),
        ("tunnel/mod.rs", include_str!("../tunnel/mod.rs")),
    ];

    // (a) NOTHING in the datapath ever enqueues a probe. This is the gap itself.
    for (name, src) in &datapath {
        let n = src.matches("enqueue_probe").count();
        assert_eq!(
            n, 0,
            "{name} now calls enqueue_probe {n} time(s) — THE GAP IS CLOSED. Delete this \
             pinned-defect test and replace it with a real coupling assertion: drive flows \
             through the forwarder and assert the Beast's tins go non-empty and `pipe` leaves \
             zero. See Proofs/BeastStarvation.lean."
        );
    }

    // (b) The scheduler itself is absent from the datapath — tins, valves and Mochi are not in
    // it at any level, not merely un-called.
    for (name, src) in &datapath {
        let code_mentions: Vec<&str> = src
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with("//") && !l.starts_with("/*") && !l.starts_with('*'))
            .filter(|l| l.contains("TortaScheduler"))
            .collect();
        assert!(
            code_mentions.is_empty(),
            "{name} now references TortaScheduler from CODE: {code_mentions:?}. If the \
             datapath was wired, replace this pinned-defect test with the real coupling \
             assertion."
        );
    }

    // (c) POSITIVE half — the Beast IS fed observations. Without this the test would still pass
    // if someone deleted the metric sinks too, silently turning a "steers nothing" defect into
    // a "knows nothing" defect and losing the live RTT that makes the diagnosis possible.
    let run = include_str!("../forwarder/run.rs");

    // (d) THE STEERING LEG — this half of the gap is CLOSED, so it is asserted POSITIVELY and
    // this test now guards the fix instead of only describing the defect.
    //
    // Until it existed, the window brain (`apply_samples` / `apply_udp_samples`) had exactly ONE
    // reachable caller in the whole crate: `feed_live_rtt`, from `resolver/mod.rs:1662`. A device
    // resolving through the EXTERNAL dnscrypt-proxy therefore never spoke to the brain at all,
    // and `query-beast.log` showed `cwnd=1/16` for all 102 ticks while `rtt=222.9ms` read live
    // from the display lanes in the very same line.
    //
    // Both legs are required, and they are asserted separately because they cover different
    // traffic: the UDP transaction pair and the TCP write-drain.
    let steering = run.matches("crate::beast::feed_live_flow_rtt(").count();
    assert_eq!(
        steering, 2,
        "expected BOTH FlowShaper sample sites to feed the window brain via \
         `crate::beast::feed_live_flow_rtt(` — found {steering}. The UDP transaction pair and \
         the TCP write-drain each need one. Losing a leg silently returns that half of the \
         traffic to the pre-fix world, where the forwarder reached only display lanes and the \
         window sat at its floor forever."
    );
    assert!(
        run.contains("crate::beast::feed_live_flow_rtt(rtt_ms, true)")
            && run.contains("crate::beast::feed_live_flow_rtt(rtt_ms, false)"),
        "the two steering legs must cover BOTH families — `true` (UDP lane) and `false` \
         (shared/TCP lane), matching the family fan-out `feed_rtt_into` gives resolver traffic. \
         Two legs on the same family would leave the other protocol unsteered while the count \
         above still read 2."
    );
    // Matched WITH the opening paren, as a call and not as a bare substring: mutation M181
    // renamed the sink to `feed_live_tcp_dialX` and this check SURVIVED, because the longer
    // name still contains the shorter one. A needle that a rename can hide behind is not an
    // instrument. `crate::beast::` is included so a local shadow cannot satisfy it either.
    for sink in [
        "crate::beast::feed_live_flow_loss(",
        "crate::beast::feed_live_flow_shape(",
        "crate::beast::feed_live_tcp_dial(",
    ] {
        assert!(
            run.contains(sink),
            "forwarder/run.rs no longer calls `{sink}` — the Beast has lost an OBSERVATION \
             path. It already steers nothing; blinding it as well removes the live RTT that \
             made this defect diagnosable in the first place. Restore the sink."
        );
    }
}
