/*
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2

    Yeah! Tortä
    Copyright 2026 Saimonokuma

    This file is part of Yeah! Tortä, dual-licensed at your option under
    EITHER the GNU Affero General Public License, version 3 or later (see
    agpl-3.0.md), OR the European Union Public Licence, version 1.2 or later
    (see EUPL-LICENSE.txt).

    Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
 */

@file:Suppress(
    "PackageNaming"
) // pillar.kuma_saimono is the app-wide namespace convention (every file); detekt's default regex
  // dislikes the underscore.

package pillar.kuma_saimono.libumdnscrypt.dns_engine.beast

import pillar.kuma_saimono.libumdnscrypt.dns_engine.BeastTunables
import pillar.kuma_saimono.libumdnscrypt.utils.logger.Logger.loge
import uniffi.torta_core.Beast
import uniffi.torta_core.TortaProfile
import uniffi.torta_core.YeahProfile

/**
 * R-Beast-Wire.4 Stage-C — THE RUST-BEAST-BACKED TUNE BRAIN (the crux of K2 slice 1).
 *
 * **THE BEAST IS THE SOLE CONGESTION BRAIN, EVERYWHERE (Socio mandate 2026-06-27 / 2026-06-29).** The
 * Solver's self-heal/rotation path ([pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver.tuneBinding])
 * must NOT carry any Kotlin congestion math — its tune decision (cwnd sizing for a won binding) routes
 * through the Rust [`Beast`] Object's `apply_sample` / `cwnd` (the same Object the hot path
 * [pillar.kuma_saimono.libumdnscrypt.dns_engine.MonokumaDnsEngine] feeds). This object is the concrete
 * `(rttMs, warmupSamples) -> cwnd` the Solver INJECTS on the live path — the "future `SolverManager`"
 * brain the Solver KDoc deferred here.
 *
 * **WHAT IT DOES (faithful 1:1 with the retired Kotlin canonical):** the old Solver built a fresh
 * `YeahController(profile = CANONICAL)`, `repeat(warmup) { yeah.apply(rtt) }`, then read
 * `yeah.cwnd` (`Solver.kt` pre-K2). This brain does EXACTLY that against the Rust Beast: construct a
 * fresh `Beast(CANONICAL, COBALT)` (the flagship profiles the live engine uses at
 * `MonokumaDnsEngine.kt:331`), warm it with `warmupSamples` RTT feeds, read back `cwnd()`. The Rust
 * Beast (`beast/{mod,yeah}.rs`) is the faithful 1:1 port of those Kotlin canonicals — same algorithm,
 * same constants, so the cwnd the Solver sees is the canonical brain's window, computed in Rust.
 *
 * **NO SINK ATTACHED (by design).** This Beast is a THERMOMETER, not the live datapath Beast — it
 * exists only to read back a healthy cwnd for a candidate binding's RTT. The Rust `push_metrics` is a
 * no-op when no sink is attached (`beast/mod.rs:264-268`), so warming it produces no dashboard noise
 * + no allocation beyond the Beast itself. The live datapath Beast (the one
 * [BeastMetricSinkImpl] is attached to) is SEPARATE + untouched.
 *
 * **CRASH-PROOF (the DEGRADED law).** The Beast is a UniFFI `#[derive(uniffi::Object)]` constructed
 * across the FFI boundary; a stale `.so` (the K1 keystone not yet regen'd by the Socio) raises
 * `UnsatisfiedLinkError`, and any native fault raises an unchecked `Throwable`. [invoke] catches
 * EVERYTHING + degrades to [BeastTunables.MIN_WINDOW] (the safe floor — a 1-window binding never
 * over-sends, it just sends less). A dead brain never crashes the self-heal path; the Solver still
 * returns a binding, conservatively sized. This mirrors the [MonokumaDnsEngine] DEGRADED-mode law.
 *
 * **STATELESS / FRESH-EACH-CALL.** A tune brain MUST be side-effect-free across calls (the Solver is
 * pure + the same RTT must yield the same cwnd for deterministic tests). Each [invoke] builds + warms
 * a FRESH Beast, reads the cwnd, then lets it drop (UniFFI `AutoCloseable` reclaims the handle). No
 * Beast state leaks between tune decisions.
 *
 * @see uniffi.torta_core.Beast the Rust engine Object
 * @see pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver.tuneBinding the Solver seam this brain feeds
 */
object BeastTuneBrain {

    /**
     * The live Rust-Beast-backed tune brain: `(rttMs, warmupSamples) -> cwnd`. Inject this into
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver.solveBinding] /
     * [pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.Solver.tuneBinding] on the live path so the
     * self-heal/rotation decision asks the Rust Beast for its healthy window — ZERO Kotlin congestion
     * math on the self-heal path (the Socio mandate, hot path AND self-heal).
     *
     * Faithful to the retired Kotlin canonical (the pre-K2 `tuneBinding` built
     * `YeahController(CANONICAL)`, warmed it `warmup` times, read `cwnd`): here a fresh
     * `Beast(CANONICAL, COBALT)` is warmed identically + its `cwnd()` read back. Same algorithm, same
     * constants — the Rust Beast is the 1:1 port (`beast/yeah.rs`).
     *
     * DEGRADED to [BeastTunables.MIN_WINDOW] on ANY FFI/native fault (stale `.so`, native fault) — the
     * safe floor, never a crash. Caller gets a conservative binding, not an exception.
     *
     * @param rttMs          the won binding's measured RTT (ms), fed to the Beast `warmupSamples` times.
     * @param warmupSamples  how many RTT feeds prime the Beast before reading cwnd (the Solver's
     *                       [pillar.kuma_saimono.libumdnscrypt.dns_engine.solver.SolverThresholds.tuneWarmupSamples]).
     * @return the Rust Beast's cwnd after warmup (1..16), or [BeastTunables.MIN_WINDOW] on FFI fault.
     */
    operator fun invoke(rttMs: Double, warmupSamples: Int): Int {
        return try {
            // A THERMOMETER Beast — Canonical YeAH (the real brain) × CoBALT CAKE (the flagship profile
            // the live datapath Beast runs, MonokumaDnsEngine.kt:331). No sink: push_metrics is a no-op
            // without one (beast/mod.rs:264-268), so this warms silently.
            val beast = Beast(YeahProfile.CANONICAL, TortaProfile.BASELINE)
            try {
                // Prime the Beast identically to the retired Kotlin canonical (repeat { yeah.apply(rtt) }):
                // feeding the measured RTT lets the Canonical YeAH brain settle its base_rtt floor + cwnd
                // to a healthy window for THIS link. A single RTT fed `warmupSamples` times is the faithful
                // mirror — the live Solver measures one RTT per candidate, then tunes against it.
                val feeds = warmupSamples.coerceAtLeast(1)
                repeat(feeds) { beast.applySample(rttMs) }
                beast.cwnd()
            } finally {
                // Reclaim the FFI handle (UniFFI Beast is AutoCloseable). try/finally so a fault mid-warm
                // never leaks a Rust-side Beast.
                @Suppress("UnsafeCallOnNullableType")
                runCatching { (beast as? AutoCloseable)?.close() }
            }
        } catch (e: Throwable) {
            // UnsatisfiedLinkError on a stale/base .so (the Beast Object symbol absent until the Socio's
            // K1 binding regen + cargo-ndk redeploy), or any native fault mid-warm. DEGRADE to the safe
            // floor — the Solver still returns a binding, conservatively sized, never throws.
            loge("BeastTuneBrain — Rust Beast unavailable, degrading tune cwnd to MIN_WINDOW", e)
            BeastTunables.MIN_WINDOW
        }
    }
}
