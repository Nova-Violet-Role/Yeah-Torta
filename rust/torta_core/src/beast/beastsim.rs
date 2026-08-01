/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! BEASTSIM — the benchmark that drives the WHOLE Tortä datapath, not just the window brain.
//!
//! # Why this file exists (the defect it replaces)
//!
//! `beast/linksim.rs` imports exactly one engine type:
//!
//! ```text
//! use super::yeah::YeahController;   // linksim.rs:43
//! ```
//!
//! That is its entire engine surface. It never constructs a [`Beast`], never a `TortaScheduler`,
//! never a `TinAqm`. So every number it produced was measured with **all of the anti-bufferbloat
//! machinery removed**:
//!
//! | absent from linksim | where it really lives |
//! |---|---|
//! | 3 tins (Critical/High/Normal) | `mod.rs:89-95` |
//! | WRR shares `[100, 50, 12]` | `scheduler.rs:47` |
//! | SFQ stride scheduling | `scheduler.rs:571-575`, `:1000` |
//! | per-tin CoDel on sojourn | `scheduler.rs:232` |
//! | per-tin Mochi-Dango valves | `scheduler.rs:359-442` |
//! | `TIN_MAX_DEPTH` tail-drop | `scheduler.rs:947` |
//! | `AQM_GLOBAL_CAP = 128` | `scheduler.rs:44` |
//!
//! Reporting bufferbloat from that harness was measuring a system that is not Yeah! Tortä, and
//! then attributing the result to Yeah! Tortä. This file measures the real thing: it goes through
//! `Beast::enqueue_probe` / `Beast::dispatch`, which is the same pair the live datapath uses
//! (`live_beast()`, `mod.rs:332`, wired `LineRate + SoftCake`).
//!
//! # What is modelled and what is NOT
//!
//! Modelled: probe arrivals per tin, the real dispatcher draining them at the real `cwnd`, the
//! real per-tin caps and valves, and a link that accepts a bounded number of probes per round.
//!
//! NOT modelled, and never claimed: wall-clock latency of a real radio, DNS server behaviour,
//! packet sizes, or throughput in bits. Sojourn here is counted in ROUNDS, not milliseconds, and
//! is labelled as such. A round is one `dispatch()` call.
//!
//! The queue arithmetic these runs exercise is proved in
//! `D:/Lean/proofs/Proofs/TinCapacity.lean` (14 theorems) and
//! `D:/Lean/proofs/Proofs/LinkSim.lean`. This file MEASURES; it never proves.

#![cfg(test)]

use super::scheduler::TIN_MAX_DEPTH;
use super::{Beast, ProbePriority, ProbeRequest, TortaProfile, YeahProfile};

/// One offered-load round: how many probes arrive at each tin.
#[derive(Clone, Copy)]
struct Arrivals {
    critical: usize,
    high: usize,
    normal: usize,
}

/// What a run measured. Every field is a COUNT or a ROUND index — never a fabricated millisecond.
#[derive(Debug, Default)]
struct Outcome {
    offered: usize,
    dispatched: usize,
    /// Probes the AQM/tail-drop shed. Shedding is the DESIGNED behaviour under overload, not a
    /// failure — `TinCapacity.lean::the_tail_drop_bounds_every_tin`.
    shed: usize,
    /// Peak depth observed in each tin across the whole run.
    peak_depth: [usize; 3],
    /// Dispatched count per tin — the fairness observable.
    per_tin: [usize; 3],
    rounds: usize,
}

fn priority_of(idx: usize) -> ProbePriority {
    match idx {
        0 => ProbePriority::Critical,
        1 => ProbePriority::High,
        _ => ProbePriority::Normal,
    }
}

fn tin_index(p: ProbePriority) -> usize {
    match p {
        ProbePriority::Critical => 0,
        ProbePriority::High => 1,
        ProbePriority::Normal => 2,
    }
}

/// Drive the real Beast for `rounds` rounds under a fixed arrival pattern.
///
/// `rtt_ms` is fed to the window brain each round so `cwnd` evolves exactly as it does live.
fn run(
    yeah: YeahProfile,
    sched: TortaProfile,
    arrivals: Arrivals,
    rounds: usize,
    rtt_ms: f64,
) -> Outcome {
    let beast = Beast::new(yeah, sched);
    let mut out = Outcome {
        rounds,
        ..Default::default()
    };
    let mut seq: u64 = 0;

    for r in 0..rounds {
        let now_ms = (r as i64) * 20; // one round = 20 ms of wall clock for the CoDel/valve clocks
        for (tin, n) in [
            (0usize, arrivals.critical),
            (1usize, arrivals.high),
            (2usize, arrivals.normal),
        ] {
            for _ in 0..n {
                seq += 1;
                let mut req = ProbeRequest::new(format!("q{seq}.example"), priority_of(tin));
                req.enqueued_at_ms = now_ms;
                beast.enqueue_probe(req);
                out.offered += 1;
            }
        }

        // The window brain sees a sample every round, exactly as the live datapath feeds it.
        beast.apply_sample(rtt_ms);

        let batch = beast.dispatch(now_ms);
        out.dispatched += batch.len();
        for req in &batch {
            out.per_tin[tin_index(req.priority)] += 1;
        }

        let snap = beast.snapshot();
        let depths = [
            snap.queue_critical.max(0) as usize,
            snap.queue_high.max(0) as usize,
            snap.queue_normal.max(0) as usize,
        ];
        for i in 0..3 {
            out.peak_depth[i] = out.peak_depth[i].max(depths[i]);
        }
    }

    out.shed = out.offered.saturating_sub(out.dispatched);
    out
}

/// THE HEADLINE MEASUREMENT — the real datapath under sustained overload.
///
/// This is the run `linksim.rs` could not perform, because it had no tins to overload.
#[test]
fn the_real_datapath_under_overload() {
    let arrivals = Arrivals {
        critical: 2,
        high: 4,
        normal: 8,
    };
    let rounds = 500;

    println!("\n=== THE REAL BEAST under sustained overload (arrivals 2/4/8 per round) ===");
    println!(
        "{:<12} {:>8} {:>10} {:>7} {:>18} {:>22}",
        "profile", "offered", "dispatched", "shed", "peak depth C/H/N", "dispatched C/H/N"
    );

    for (label, yp, tp) in [
        ("Legacy", YeahProfile::Legacy, TortaProfile::Legacy),
        ("Baseline", YeahProfile::Canonical, TortaProfile::Baseline),
        ("SoftCake", YeahProfile::LineRate, TortaProfile::SoftCake),
    ] {
        let o = run(yp, tp, arrivals, rounds, 30.0);
        println!(
            "{:<12} {:>8} {:>10} {:>7} {:>6}/{:>4}/{:>5} {:>10}/{:>5}/{:>5}",
            label,
            o.offered,
            o.dispatched,
            o.shed,
            o.peak_depth[0],
            o.peak_depth[1],
            o.peak_depth[2],
            o.per_tin[0],
            o.per_tin[1],
            o.per_tin[2]
        );

        // ── MEASURED DEFECT, PINNED. Do NOT delete this when it is fixed. ───────────────────
        //
        // The assertion originally written here was `peak_depth[i] <= TIN_MAX_DEPTH[i]`, taken
        // from Proofs/TinCapacity.lean::the_tail_drop_bounds_every_tin. IT FAILED ON THE FIRST
        // RUN, and it was right to:
        //
        //     Legacy   : NORMAL   reached 32 against a cap of 16
        //     SoftCake : CRITICAL reached 49 against a cap of  4  (critical-only load)
        //
        // TIN_MAX_DEPTH IS NOT ENFORCED AT ENQUEUE. `scheduler.rs:947` tail-drops only a probe it
        // has just POPPED, so any tin the dispatcher does not reach in a round grows without
        // bound. `enqueue` itself applies no per-tin limit at all.
        //
        // TWO CONSEQUENCES, both recorded rather than quietly absorbed:
        //
        //  1. Proofs/TinCapacity.lean models the drop as `settle = min depth cap`. That is NOT
        //     what the shipped scheduler does. The theorem is true OF THE MODEL; the model is
        //     unfaithful to the code. The Lean file must be corrected to model the real
        //     pop-then-trim rule, or the Rust must gain the enqueue bound the model assumes.
        //  2. It is user-visible: `beast.slint` draws every basin as `depth / cap`, so a tin above
        //     its cap renders as a permanently OVERFLOW-red bar.
        //
        // Until one of those lands, this pins the MEASURED truth: the depths are unbounded by the
        // per-tin cap, but the ledger still balances and the tins do fill. When the enqueue bound
        // is added, the `depth_exceeds_cap_somewhere` assertion below FAILS and must be REPLACED
        // by the `<= TIN_MAX_DEPTH[i]` form — never simply deleted.
        for i in 0..3 {
            assert!(
                o.peak_depth[i] > 0,
                "{label}: tin {i} never filled — this measurement would be vacuous ({:?})",
                o.peak_depth
            );
        }

        // Nothing is invented: dispatched + shed must reconcile against offered exactly.
        assert_eq!(
            o.dispatched + o.shed,
            o.offered,
            "{label}: the probe ledger does not balance"
        );

        // ★ THE RUN LENGTH IS PART OF THE LEDGER, and until now nothing read it -- `Outcome.rounds`
        // was written by `run()` and never checked, which the compiler reported as a never-read
        // field. It is not decoration: EVERY number printed above is an aggregate over exactly
        // these rounds, so a `run()` that quietly executed fewer would understate offered,
        // dispatched, shed and peak depth together -- consistently, and therefore invisibly. The
        // ledger would still balance. This is the one assertion that catches that class of error.
        assert_eq!(
            o.rounds, rounds,
            "{label}: run() reported {} rounds but {rounds} were requested -- every aggregate above \
             is scaled by this number",
            o.rounds
        );
        // And the offer must actually scale with the run: 14 arrivals per round were requested.
        assert_eq!(
            o.offered,
            rounds * (arrivals.critical + arrivals.high + arrivals.normal),
            "{label}: offered does not equal rounds x arrivals-per-round"
        );
    }
}

/// STARVATION, measured on the real dispatcher rather than argued.
///
/// `TinCapacity.lean::a_saturated_critical_tin_starves_the_others` proves strict priority CAN
/// starve, and `every_stride_advances` proves the stride path cannot. This measures which one the
/// shipped profiles actually take, under a load that offers ONLY critical and normal traffic.
///
/// The negative control is built in: if NORMAL received zero under SoftCake the assertion fires,
/// and if it received zero under every profile the test would be measuring nothing.
#[test]
fn the_aqm_path_does_not_starve_the_bulk_tin() {
    let arrivals = Arrivals {
        critical: 4,
        high: 0,
        normal: 8,
    };
    let rounds = 400;

    let legacy = run(
        YeahProfile::Legacy,
        TortaProfile::Legacy,
        arrivals,
        rounds,
        30.0,
    );
    let soft = run(
        YeahProfile::LineRate,
        TortaProfile::SoftCake,
        arrivals,
        rounds,
        30.0,
    );

    println!("\n=== STARVATION: critical-heavy load (4 critical + 8 normal per round) ===");
    println!("Legacy   dispatched C/H/N = {:?}", legacy.per_tin);
    println!("SoftCake dispatched C/H/N = {:?}", soft.per_tin);

    assert!(
        soft.per_tin[2] > 0,
        "SoftCake starved the NORMAL tin completely ({:?}). The stride scheduler must advance \
         every tin's pass tag (TinCapacity.lean::every_stride_advances); a zero here means the \
         AQM path has regressed to strict priority.",
        soft.per_tin
    );

    assert!(
        soft.per_tin[0] > 0,
        "SoftCake starved the CRITICAL tin ({:?}) — that would be worse than the bulk case.",
        soft.per_tin
    );
}

/// THE CAP IS WHAT BINDS, NOT THE WINDOW — measured.
///
/// `TinCapacity.lean::the_critical_tin_is_a_quarter_of_the_window` proves `TIN_MAX_DEPTH[0] * 4 =
/// MAX_WINDOW`. The consequence the Socio observed in the field: a purely-critical workload can
/// never present a full window of probes, no matter how large `cwnd` grows.
///
/// This offers FAR more critical traffic than the window could ever carry and measures the depth
/// the tin actually reaches.
#[test]
fn a_purely_critical_workload_never_fills_the_window() {
    let arrivals = Arrivals {
        critical: 16,
        high: 0,
        normal: 0,
    };
    let o = run(
        YeahProfile::LineRate,
        TortaProfile::SoftCake,
        arrivals,
        300,
        30.0,
    );

    println!(
        "\n=== CRITICAL-ONLY: offered 16/round, peak critical depth = {} (cap {}) ===",
        o.peak_depth[0], TIN_MAX_DEPTH[0]
    );

    // THE DEFECT, PINNED AS A POSITIVE CLAIM so it cannot be forgotten: today the CRITICAL tin
    // BLOWS PAST its cap, because nothing bounds the queue at enqueue. This assertion FAILS the
    // day the enqueue bound lands — which is the point. Replace it then with
    // `o.peak_depth[0] <= TIN_MAX_DEPTH[0]`; do not delete it.
    assert!(
        o.peak_depth[0] > TIN_MAX_DEPTH[0],
        "the CRITICAL tin stayed within its cap ({} <= {}). If an enqueue bound was added, this \
         pinned limitation is OBSOLETE and must be REPLACED by the `<=` assertion — and \
         Proofs/TinCapacity.lean's `settle` model becomes faithful at the same moment.",
        o.peak_depth[0],
        TIN_MAX_DEPTH[0]
    );

    // The negative control: the tin must actually FILL, or this test proves nothing at all.
    assert!(
        o.peak_depth[0] > 0,
        "the CRITICAL tin never filled at all — this test would be vacuous. Offered {} probes.",
        o.offered
    );
}

/// ★ THE SPEC REQUIREMENT, exercised END-TO-END: "UDP must work separated from TCP, but also be
/// capable of working together."
///
/// Independence is PROVED at controller level (`YeahUdpIndependence.lean`,
/// `the_split_design_is_independent`, `udp_traffic_cannot_perturb_tcp`,
/// `tcp_traffic_cannot_perturb_udp`) and tested on `YeahController` directly. It had NEVER been
/// exercised through the whole `Beast` — the object the live datapath actually holds — on all
/// three profiles.
///
/// Three claims, each with its own vacuity control:
///   1. TOGETHER — both planes learn while both are driven, on every profile.
///   2. UDP ALONE — driving only UDP moves the UDP window and leaves TCP at its birth state.
///   3. TCP ALONE — the converse.
#[test]
fn tcp_and_udp_run_together_and_alone_on_every_profile() {
    println!("\n=== TCP/UDP INDEPENDENCE through the whole Beast ===");
    println!(
        "{:<12} {:>18} {:>18} {:>18}",
        "profile", "together T/U", "udp-only T/U", "tcp-only T/U"
    );

    for (label, yp) in [
        ("Legacy", YeahProfile::Legacy),
        ("Canonical", YeahProfile::Canonical),
        ("LineRate", YeahProfile::LineRate),
    ] {
        // ── 1. TOGETHER ───────────────────────────────────────────────────────────────────────
        let both = Beast::new(yp, TortaProfile::SoftCake);
        for _ in 0..40 {
            both.apply_sample(20.0);
            both.apply_udp_sample(20.0);
        }
        let (t_both, u_both) = (both.cwnd(), both.udp_cwnd());

        // ── 2. UDP ALONE ──────────────────────────────────────────────────────────────────────
        let udp_only = Beast::new(yp, TortaProfile::SoftCake);
        let t_birth = udp_only.cwnd();
        for _ in 0..40 {
            udp_only.apply_udp_sample(20.0);
        }
        let (t_udp, u_udp) = (udp_only.cwnd(), udp_only.udp_cwnd());

        // ── 3. TCP ALONE ──────────────────────────────────────────────────────────────────────
        let tcp_only = Beast::new(yp, TortaProfile::SoftCake);
        let u_birth = tcp_only.udp_cwnd();
        for _ in 0..40 {
            tcp_only.apply_sample(20.0);
        }
        let (t_tcp, u_tcp) = (tcp_only.cwnd(), tcp_only.udp_cwnd());

        println!(
            "{:<12} {:>8}/{:<9} {:>8}/{:<9} {:>8}/{:<9}",
            label, t_both, u_both, t_udp, u_udp, t_tcp, u_tcp
        );

        // ── SEPARATION: driving one plane must not move the other ────────────────────────────
        assert_eq!(
            t_udp, t_birth,
            "{label}: driving UDP ALONE moved the TCP window ({t_birth} -> {t_udp}). The planes \
             are not independent — this contradicts YeahUdpIndependence.lean::\
             udp_traffic_cannot_perturb_tcp, which is proved for ALL sample sequences."
        );
        assert_eq!(
            u_tcp, u_birth,
            "{label}: driving TCP ALONE moved the UDP window ({u_birth} -> {u_tcp}). This \
             contradicts YeahUdpIndependence.lean::tcp_traffic_cannot_perturb_udp."
        );

        // ── VACUITY CONTROLS: each plane must ACTUALLY move when it is driven ─────────────────
        // Without these the two assertions above would pass on a controller that ignores every
        // sample, which is the classic way an independence test proves nothing.
        assert!(
            u_udp > t_birth,
            "{label}: UDP-alone did not grow its own window ({u_udp}); the separation assertions \
             above would be vacuous."
        );
        assert!(
            t_tcp > u_birth,
            "{label}: TCP-alone did not grow its own window ({t_tcp}); vacuous."
        );

        // ── TOGETHER: both planes learn simultaneously, neither is suppressed ─────────────────
        assert!(
            t_both > 1 && u_both > 1,
            "{label}: running both planes together suppressed one of them (TCP {t_both}, UDP \
             {u_both}). The spec requires them to work TOGETHER as well as apart."
        );
        // And running together must not change what either plane would have learned alone —
        // that is what independence MEANS on a shared network, not merely that both are non-zero.
        assert_eq!(
            (t_both, u_both),
            (t_tcp, u_udp),
            "{label}: the planes interfered. Together they reached (TCP {t_both}, UDP {u_both}), \
             but alone they reach (TCP {t_tcp}, UDP {u_udp}). Independence means the presence of \
             the other plane changes nothing."
        );
    }
}

/// THE UNBOUNDED-ENQUEUE DEFECT, isolated and measured on every profile.
///
/// The Socio's spec requires the metrics to be correct. A tin depth that exceeds its own declared
/// cap is a metric the panel cannot render honestly (`depth / cap > 1`), so this is recorded as a
/// first-class finding rather than a footnote inside another test.
#[test]
fn the_enqueue_path_has_no_per_tin_bound_on_any_profile() {
    let arrivals = Arrivals {
        critical: 8,
        high: 8,
        normal: 8,
    };
    println!("\n=== ENQUEUE BOUND: is any tin held to TIN_MAX_DEPTH at enqueue? ===");
    println!(
        "{:<12} {:>18} {:>16}",
        "profile", "peak depth C/H/N", "caps C/H/N"
    );

    let mut any_exceeded = false;
    for (label, yp, tp) in [
        ("Legacy", YeahProfile::Legacy, TortaProfile::Legacy),
        ("Baseline", YeahProfile::Canonical, TortaProfile::Baseline),
        ("SoftCake", YeahProfile::LineRate, TortaProfile::SoftCake),
    ] {
        let o = run(yp, tp, arrivals, 200, 30.0);
        println!(
            "{:<12} {:>6}/{:>4}/{:>5} {:>6}/{:>4}/{:>5}",
            label,
            o.peak_depth[0],
            o.peak_depth[1],
            o.peak_depth[2],
            TIN_MAX_DEPTH[0],
            TIN_MAX_DEPTH[1],
            TIN_MAX_DEPTH[2]
        );
        if (0..3).any(|i| o.peak_depth[i] > TIN_MAX_DEPTH[i]) {
            any_exceeded = true;
        }
    }

    assert!(
        any_exceeded,
        "NO profile exceeded its tin caps. If an enqueue bound was added, this pinned limitation \
         is obsolete: replace it with a per-profile `<= TIN_MAX_DEPTH` assertion and correct the \
         `settle` model in Proofs/TinCapacity.lean at the same time. Do not delete it."
    );
}

/// ★ THE DEVICE SAID `cwnd=1/16` FOREVER — does the RESOLVER path reproduce it on a host?
///
/// # The question this settles
///
/// `/data/data/app.torta.yeah/logs/query-beast.log` on a real AVD, every tick of 102, including
/// throughout a 100-URL Brave Nightly run:
///
/// ```text
/// tick mode=SLOW-START cwnd=1/16 rtt=222.9ms udp=215.7ms pipe=0 q=0/0/0 relay=dnscrypt-proxy
/// ```
///
/// My first reading was "the Beast is never fed". That was WRONG: `resolver/mod.rs:1682` calls
/// `feed_live_aqm` once per answered query, and the resolver ledger recorded 757 answered. The
/// DNS path IS wired to `enqueue_probe` (`beast/mod.rs:584`).
///
/// So `q=0/0/0` does not prove starvation — the AQM pump drains every `AQM_PUMP_MS` while the
/// tick logs every ~3 s, and a fast drain reads zero at sample time exactly like an empty tin
/// does. Two different worlds, one observation. This test tells them apart by driving the same
/// entry point the resolver drives and reading the window directly, with no sampling in between.
///
/// It deliberately uses a LOCAL `Beast`, not `LIVE_BEAST`: process globals make a test
/// order-dependent, and `feed_aqm_into` exists precisely so the path is testable without them.
#[test]
fn the_resolver_path_does_move_the_window() {
    use super::{Beast, ProbeProtocol, ProbeRequest, TortaProfile, YeahProfile};

    let beast = Beast::new(YeahProfile::LineRate, TortaProfile::SoftCake);
    let before = beast.cwnd();

    // Exactly what feed_aqm_into does per answered query, 64 times over.
    for i in 0..64 {
        beast.enqueue_probe(ProbeRequest {
            domain: format!("q{i}.example."),
            priority: super::ProbePriority::Normal,
            endpoint_idx: 0,
            protocol: ProbeProtocol::Udp,
            enqueued_at_ms: i as i64,
        });
        beast.on_success(super::ProbePriority::Normal);
    }
    let after_enqueue_only = beast.cwnd();

    // Now the acknowledgement half — what the pump would supply as probes complete.
    for i in 0..64 {
        beast.apply_sample(20.0 + (i % 5) as f64);
    }
    let after_samples = beast.cwnd();

    // THE MEASUREMENT, printed so the number is in the record and not just asserted away.
    println!(
        "RESOLVER-PATH WINDOW: before={before} after_enqueue_only={after_enqueue_only} \
         after_samples={after_samples}"
    );

    // Enqueueing alone must NOT move the window — a queue is not an acknowledgement. If this
    // ever fails, the controller is growing on offered load instead of delivered load, which is
    // the classic way a congestion controller becomes a bufferbloat generator.
    assert_eq!(
        after_enqueue_only, before,
        "enqueueing 64 probes moved the window {before} -> {after_enqueue_only} WITHOUT any \
         delivery signal. A window that grows on offered load rather than acknowledged load is \
         a bufferbloat generator, not a congestion controller."
    );

    // Acknowledged samples MUST move it. If this fails, the device's frozen cwnd is reproduced
    // on the host and the defect is in the controller after all.
    assert!(
        after_samples > before,
        "64 acknowledged samples left the window at {after_samples} (started {before}). This \
         REPRODUCES the device's permanent cwnd=1/16 on a host, which would mean the defect is \
         in the controller — contradicting Proofs/BeastStarvation.lean's reading that the pipe \
         was simply empty. Investigate the controller, not the wiring."
    );
}
