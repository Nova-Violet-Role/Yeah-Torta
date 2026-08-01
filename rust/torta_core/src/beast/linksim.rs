/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! A DETERMINISTIC bottleneck-link simulator, for MEASURING what Lean cannot prove.
//!
//! # Why this file exists, stated so it cannot be misread
//!
//! Everything proved in `D:/Lean/proofs/Proofs/` about YeAH concerns STATE: window bounds,
//! per-family independence, the pacing floor, the routing law. Lean settles those for all
//! inputs. Lean says NOTHING about goodput, latency-under-load, or fairness — those are
//! properties of the algorithm meeting a network, and no theorem in this repo bears on them.
//!
//! That gap was being papered over with prose ("kernel-grade", "zero speed penalty"). This
//! module replaces the prose with numbers. **Every result it produces is MEASURED, never
//! PROVED, and is a measurement against a MODEL of a link, not against the Internet.**
//!
//! # What it is honest about
//!
//! This is a fluid/round model: fixed-size rounds, a FIFO bottleneck queue of finite depth,
//! constant propagation delay. It captures standing-queue growth (bufferbloat) and tail-drop
//! loss. It does NOT model: ACK clocking, packet reordering, variable MTU, cross-traffic
//! bursts, wireless loss, receiver windows, or coalescing. A result here is evidence about the
//! control law's shape, not a throughput promise on a real link.
//!
//! # What makes it non-circular
//!
//! It drives the REAL [`YeahController`] — `apply`, `apply_udp`, `on_loss_or_timeout`,
//! `on_udp_loss_or_timeout`, `cwnd`, `udp_cwnd` — never a reimplementation. If the shipped
//! controller changes, these numbers change with it. The reference controller it is compared
//! against is a textbook Reno (AIMD, halve-on-loss), written here in ten lines precisely so
//! that it is auditable and obviously not tuned in our favour.
//!
//! The link model's own invariants (bytes are conserved; the queue never goes negative and
//! never exceeds its depth) are PROVED for all inputs in
//! `D:/Lean/proofs/Proofs/LinkSim.lean` — because a simulator that can silently create or
//! destroy bytes can manufacture any goodput figure you like.

#![cfg(test)]

use super::yeah::YeahController;
use super::YeahProfile;

/// One segment on the wire — the same 1360 B the forwarder paces in (`shape.rs:63`).
pub(crate) const SEG: u64 = 1360;

/// A bottleneck link: capacity, propagation delay, and a finite FIFO queue.
#[derive(Debug, Clone)]
pub(crate) struct Link {
    /// Drain rate in bytes per round.
    pub capacity_per_round: u64,
    /// One-way propagation delay in ms (the RTT floor: 2× this).
    pub prop_delay_ms: f64,
    /// Queue depth in bytes. A SMALL value is a well-managed link; a LARGE one is exactly the
    /// oversized dumb buffer that causes bufferbloat.
    pub queue_limit: u64,
    /// Bytes currently sitting in the queue.
    pub queued: u64,
}

/// What one round did. Every field is a byte count or a delay, so the ledger can be checked.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Round {
    pub offered: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub delivered: u64,
    /// Standing-queue delay seen by this round's traffic, in ms.
    pub queue_delay_ms: f64,
    /// The RTT the sender measures: propagation + standing queue.
    pub rtt_ms: f64,
}

impl Link {
    pub(crate) fn new(capacity_per_round: u64, prop_delay_ms: f64, queue_limit: u64) -> Self {
        Self { capacity_per_round, prop_delay_ms, queue_limit, queued: 0 }
    }

    /// Offer `offered` bytes. Tail-drop what will not fit, drain one round's capacity, and
    /// report the RTT a sender would measure.
    ///
    /// THE LEDGER, proved in `LinkSim.lean`: `accepted + dropped == offered`, `delivered <=
    /// queued_before + accepted`, and the queue stays within `[0, queue_limit]`.
    pub(crate) fn step(&mut self, offered: u64) -> Round {
        let room = self.queue_limit.saturating_sub(self.queued);
        let accepted = offered.min(room);
        let dropped = offered - accepted;
        self.queued += accepted;
        let delivered = self.capacity_per_round.min(self.queued);
        self.queued -= delivered;
        // Standing-queue delay: what is left in the queue must drain at capacity before a
        // newly-arriving byte leaves. This is the bufferbloat signal a delay-based controller
        // is supposed to see and a loss-based one is not.
        let queue_delay_ms = if self.capacity_per_round == 0 {
            0.0
        } else {
            (self.queued as f64 / self.capacity_per_round as f64) * (2.0 * self.prop_delay_ms)
        };
        let rtt_ms = 2.0 * self.prop_delay_ms + queue_delay_ms;
        Round { offered, accepted, dropped, delivered, queue_delay_ms, rtt_ms }
    }
}

/// A sender: something that answers "how many segments may I put on the wire this round?" and
/// is told what happened.
pub(crate) trait Sender {
    fn window_segments(&self) -> u64;
    fn on_sample(&mut self, rtt_ms: f64);
    fn on_loss(&mut self);
    fn name(&self) -> &'static str;
}

/// The REAL shipped controller, TCP family.
pub(crate) struct YeahTcp {
    pub c: YeahController,
    pub label: &'static str,
}

impl Sender for YeahTcp {
    fn window_segments(&self) -> u64 {
        self.c.cwnd().max(1) as u64
    }
    fn on_sample(&mut self, rtt_ms: f64) {
        self.c.apply(rtt_ms);
    }
    fn on_loss(&mut self) {
        self.c.on_loss_or_timeout();
    }
    fn name(&self) -> &'static str {
        self.label
    }
}

/// The REAL shipped controller, independent UDP family — the thing this whole rung is about.
pub(crate) struct YeahUdp {
    pub c: YeahController,
    pub label: &'static str,
}

impl Sender for YeahUdp {
    fn window_segments(&self) -> u64 {
        self.c.udp_cwnd().max(1) as u64
    }
    fn on_sample(&mut self, rtt_ms: f64) {
        self.c.apply_udp(rtt_ms);
    }
    fn on_loss(&mut self) {
        self.c.on_udp_loss_or_timeout();
    }
    fn name(&self) -> &'static str {
        self.label
    }
}

/// Textbook Reno, deliberately naive and deliberately NOT tuned for this link: additive
/// increase of one segment per round, multiplicative decrease by half on loss. Ten lines so
/// that nobody has to take my word for what it does. It has NO window ceiling, which is the
/// point of comparison: it will fill whatever buffer it is given.
pub(crate) struct RenoRef {
    pub cwnd: u64,
}

impl Sender for RenoRef {
    fn window_segments(&self) -> u64 {
        self.cwnd.max(1)
    }
    fn on_sample(&mut self, _rtt_ms: f64) {
        self.cwnd += 1;
    }
    fn on_loss(&mut self) {
        self.cwnd = (self.cwnd / 2).max(1);
    }
    fn name(&self) -> &'static str {
        "Reno (reference)"
    }
}

/// The outcome of a run — the two numbers the whole argument turns on, plus the ledger.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Outcome {
    pub delivered: u64,
    pub offered: u64,
    pub dropped: u64,
    pub rounds: u64,
    /// Mean standing-queue delay in ms. THE bufferbloat number: how long a packet from any
    /// other application waits behind this flow.
    pub mean_queue_delay_ms: f64,
    /// Worst standing-queue delay seen. The number a video call actually feels.
    pub max_queue_delay_ms: f64,
    pub final_window: u64,
    /// The LARGEST window the sender ever used during the run. The final window is NOT a
    /// valid proxy for this: a controller can overshoot, fill the buffer, and settle back
    /// to capacity -- at which point the standing queue never drains again.
    pub peak_window: u64,
}

impl Outcome {
    /// Goodput as a fraction of what the link could have carried. 1.0 = the flow kept the
    /// bottleneck perfectly busy.
    pub(crate) fn link_utilisation(&self, link_capacity_per_round: u64) -> f64 {
        if self.rounds == 0 || link_capacity_per_round == 0 {
            return 0.0;
        }
        self.delivered as f64 / (self.rounds * link_capacity_per_round) as f64
    }
}

/// Run one sender over one link for `rounds` rounds, fully deterministically.
pub(crate) fn run(sender: &mut dyn Sender, link: &mut Link, rounds: u64) -> Outcome {
    let mut delivered = 0u64;
    let mut offered_total = 0u64;
    let mut dropped_total = 0u64;
    let mut delay_sum = 0.0f64;
    let mut delay_max = 0.0f64;
    let mut peak_window = 0u64;
    for _ in 0..rounds {
        let w = sender.window_segments();
        if w > peak_window { peak_window = w; }
        let offered = w * SEG;
        let r = link.step(offered);
        delivered += r.delivered;
        offered_total += r.offered;
        dropped_total += r.dropped;
        delay_sum += r.queue_delay_ms;
        if r.queue_delay_ms > delay_max {
            delay_max = r.queue_delay_ms;
        }
        // Loss is the tail-drop; otherwise the round's measured RTT is the sample.
        if r.dropped > 0 {
            sender.on_loss();
        } else {
            sender.on_sample(r.rtt_ms);
        }
    }
    Outcome {
        delivered,
        offered: offered_total,
        dropped: dropped_total,
        rounds,
        mean_queue_delay_ms: if rounds == 0 { 0.0 } else { delay_sum / rounds as f64 },
        max_queue_delay_ms: delay_max,
        final_window: sender.window_segments(),
        peak_window,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ★ THE LEDGER, checked in Rust against the same statement `LinkSim.lean` proves.
    ///
    /// `Round` documents itself as "every field is a byte count or a delay, so the ledger can be
    /// checked" — and until now NOTHING checked it. `offered` and `dropped` were written by
    /// `step()` and read by nobody, which is exactly what the compiler was reporting: not that the
    /// fields are pointless, but that the ledger they exist for was never verified on this side of
    /// the wall. A proof about a model the code never confirms is a proof about a document.
    ///
    /// Three invariants, over a spread of link shapes and offers rather than one lucky case:
    ///   1. CONSERVATION   accepted + dropped == offered   (nothing invented, nothing vanished)
    ///   2. CAUSALITY      delivered <= accepted           (you cannot deliver what you refused)
    ///   3. BOUNDEDNESS    queued <= queue_limit           (the FIFO never exceeds its own limit)
    #[test]
    fn the_link_ledger_balances_for_every_offer() {
        for &cap in &[1u64, 7, 10 * SEG, 64 * SEG] {
            for &limit in &[0u64, SEG, 10 * SEG, 100 * 10 * SEG] {
                let mut link = Link::new(cap, 20.0, limit);
                for &offered in &[0u64, 1, SEG, 3 * SEG, 40 * SEG, 1000 * SEG] {
                    let r = link.step(offered);
                    assert_eq!(
                        r.accepted + r.dropped,
                        r.offered,
                        "CONSERVATION broken: cap={cap} limit={limit} offered={offered} -> {r:?}"
                    );
                    assert_eq!(r.offered, offered, "step() must report the offer it was given");
                    assert!(
                        r.delivered <= r.accepted,
                        "CAUSALITY broken: delivered {} > accepted {} ({r:?})",
                        r.delivered,
                        r.accepted
                    );
                    assert!(
                        link.queued <= limit,
                        "BOUNDEDNESS broken: queued {} > queue_limit {limit}",
                        link.queued
                    );
                }
            }
        }
    }

    /// A zero-capacity link with no buffer must drop EVERYTHING and deliver nothing -- the negative
    /// control for the ledger above. Without it, a `step()` that silently returned an all-zero
    /// Round would satisfy conservation and causality and look perfectly healthy.
    #[test]
    fn a_dead_link_drops_all_of_it_and_says_so() {
        let mut link = Link::new(0, 20.0, 0);
        let r = link.step(10 * SEG);
        assert_eq!(r.offered, 10 * SEG);
        assert_eq!(r.dropped, 10 * SEG, "a link with no capacity and no buffer must drop the lot");
        assert_eq!(r.accepted, 0);
        assert_eq!(r.delivered, 0);
    }

    /// ★ THE RUN-LEVEL LEDGER, and the reason `Outcome.offered`, `.dropped` and `.rounds` existed
    /// unread. `Outcome`'s own doc calls them "the ledger", and every published comparison in this
    /// module quotes goodput and delay while nothing ever checked that the run's totals ADD UP.
    /// That is the weak point of a benchmark: a `run()` that quietly dropped rounds, or double
    /// counted an offer, would still print a beautiful table.
    ///
    /// Checked across all three senders so no controller gets a private accounting rule:
    ///   1. `rounds` is the count that was ASKED FOR -- a run that silently shortens is a lie
    ///      about every per-round average derived from it (mean_queue_delay_ms divides by it).
    ///   2. `delivered + dropped <= offered`, with the slack being exactly what is still queued.
    ///   3. `offered` is 0 only when nothing was asked of the link.
    ///   4. every sender reports a non-empty, DISTINCT `name()` -- the label a result is attributed
    ///      to, which is worthless if two controllers answer the same string.
    #[test]
    fn the_run_ledger_adds_up_for_every_sender() {
        // ALL THREE PROFILES, both families. Legacy / Canonical / LineRate are not variants of a
        // test fixture -- they are the shipped congestion personalities, carried across YeAH TCP,
        // YeAH UDP and the rest of the engine family (Engine Room, netstack forwarder, the Beast,
        // where they pair with TortaProfile Legacy / Baseline / SoftCake). A ledger checked on
        // Canonical alone would leave two thirds of the shipped surface unaccounted, and the
        // profiles differ precisely in how aggressively they offer -- which is the input to every
        // number in this ledger.
        let profiles = [
            ("Legacy", YeahProfile::Legacy),
            ("Canonical", YeahProfile::Canonical),
            ("LineRate", YeahProfile::LineRate),
        ];

        // `name()` returns `self.label`, so exercising it is also what proves the label field is
        // a real attribution channel and not decoration.
        let mut names: Vec<String> = Vec::new();
        for (pname, p) in profiles {
            let mut tcp = yeah_tcp(p);
            let mut udp = yeah_udp(p);
            let mut reno = RenoRef { cwnd: 1 };
            let senders: Vec<&mut dyn Sender> = vec![&mut tcp, &mut udp, &mut reno];

            for s in senders {
                let mut l = bloated_link();
                let o = run(s, &mut l, 200);
                let who = format!("{pname}/{}", s.name());
                assert_eq!(o.rounds, 200, "{who}: run reported {} rounds, 200 were asked for", o.rounds);
                assert!(o.offered > 0, "{who}: a 200-round run offered nothing");
                assert!(
                    o.delivered + o.dropped <= o.offered,
                    "{who}: delivered {} + dropped {} exceeds offered {}",
                    o.delivered, o.dropped, o.offered
                );
                assert_eq!(
                    o.offered - o.delivered - o.dropped,
                    l.queued,
                    "{who}: the unaccounted bytes must be exactly what is still in the queue"
                );
                // Reno is the shared reference controller, so it repeats across profiles by design;
                // only the two YeAH families carry a per-profile identity worth uniqueness-checking.
                if s.name() != "Reno (reference)" {
                    names.push(who);
                }
            }
        }
        // Six identities expected: 3 profiles x 2 YeAH families. If any two collide, a result
        // cannot be attributed to the profile/family that produced it.
        assert_eq!(names.len(), 6, "expected 3 profiles x 2 YeAH families, got {names:?}");
        for n in &names {
            assert!(!n.is_empty(), "a sender reported an empty name -- results cannot be attributed");
        }
        let mut uniq = names.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), names.len(), "two profile/family pairs share a name: {names:?}");
    }

    /// A zero-round run must produce an all-zero ledger rather than a division by `rounds`.
    /// This is the negative control for the test above: it is the one input where an averaging
    /// bug shows up as NaN instead of a number, and NaN compares false against every assertion.
    #[test]
    fn a_zero_round_run_is_empty_not_nan() {
        let mut s = yeah_tcp(YeahProfile::Canonical);
        let mut l = bloated_link();
        let o = run(&mut s, &mut l, 0);
        assert_eq!(o.rounds, 0);
        assert_eq!(o.offered, 0);
        assert_eq!(o.dropped, 0);
        assert_eq!(o.delivered, 0);
        assert!(o.mean_queue_delay_ms.is_finite(), "mean delay went NaN on a zero-round run");
    }

    /// A deliberately BLOATED link: 100 rounds' worth of buffer at the bottleneck. This is the
    /// canonical bufferbloat setup — a dumb oversized FIFO on the last mile.
    fn bloated_link() -> Link {
        // 10 segments/round of capacity, 20 ms one-way, 100 rounds of buffer.
        Link::new(10 * SEG, 20.0, 100 * 10 * SEG)
    }

    fn yeah_udp(p: YeahProfile) -> YeahUdp {
        YeahUdp { c: YeahController::with_profile(p), label: "YeAH-UDP" }
    }

    fn yeah_tcp(p: YeahProfile) -> YeahTcp {
        YeahTcp { c: YeahController::with_profile(p), label: "YeAH-TCP" }
    }

    /// THE LEDGER: the simulator cannot create or destroy bytes. If this fails, every number
    /// this module has ever printed is void. Proved for all inputs in `LinkSim.lean`; checked
    /// here against the real implementation.
    #[test]
    fn the_link_conserves_every_byte() {
        let mut link = bloated_link();
        let mut queued_expected = 0u64;
        let mut total_delivered = 0u64;
        let mut total_dropped = 0u64;
        let mut total_offered = 0u64;
        // A deliberately varied offer pattern, including overfilling the queue.
        for i in 0..500u64 {
            let offered = (i % 37) * SEG;
            let r = link.step(offered);
            assert_eq!(r.accepted + r.dropped, r.offered, "round {i}: accepted+dropped != offered");
            queued_expected = queued_expected + r.accepted - r.delivered;
            assert_eq!(link.queued, queued_expected, "round {i}: queue ledger diverged");
            assert!(link.queued <= link.queue_limit, "round {i}: queue exceeded its depth");
            total_delivered += r.delivered;
            total_dropped += r.dropped;
            total_offered += r.offered;
        }
        assert_eq!(
            total_delivered + total_dropped + link.queued,
            total_offered,
            "bytes were created or destroyed across the whole run"
        );
        // NEGATIVE CONTROL: the run actually exercised both drop and delivery, so the ledger
        // above was not trivially satisfied by an idle link.
        assert!(total_dropped > 0, "the ledger test never dropped a byte -- it proved nothing");
        assert!(total_delivered > 0, "the ledger test never delivered a byte");
    }

    /// MEASURED, NOT PROVED — the headline comparison, on a bloated link.
    ///
    /// The claim under test is the Reviewer's third premise: "eliminates bufferbloat without
    /// sacrificing speed". Two numbers decide it, and they trade off against each other, so
    /// both must be reported together or the result is propaganda:
    ///   - link utilisation (speed)
    ///   - standing-queue delay (what every OTHER application on the link feels)
    ///
    /// A window-capped controller CANNOT fill a 100-round buffer, so it should show a far
    /// lower queue delay. Whether it pays for that in utilisation is exactly the open
    /// question, and this test prints the answer rather than assuming it.
    #[test]
    fn bufferbloat_and_speed_measured_together_on_a_bloated_link() {
        let rounds = 2000u64;
        let cap = bloated_link().capacity_per_round;

        let mut results: Vec<(String, Outcome)> = Vec::new();
        for (name, p) in [
            ("Legacy", YeahProfile::Legacy),
            ("Canonical", YeahProfile::Canonical),
            ("LineRate", YeahProfile::LineRate),
        ] {
            let mut l = bloated_link();
            let mut s = yeah_udp(p);
            results.push((format!("YeAH-UDP/{name}"), run(&mut s, &mut l, rounds)));
            let mut l2 = bloated_link();
            let mut s2 = yeah_tcp(p);
            results.push((format!("YeAH-TCP/{name}"), run(&mut s2, &mut l2, rounds)));
        }
        let mut l3 = bloated_link();
        let mut reno = RenoRef { cwnd: 1 };
        results.push(("Reno (reference)".to_string(), run(&mut reno, &mut l3, rounds)));

        println!("\n=== MEASURED on a bloated link (cap {cap} B/round, 100-round buffer, {rounds} rounds) ===");
        println!("{:<22} {:>10} {:>14} {:>14} {:>8}", "sender", "util", "mean qdelay", "max qdelay", "cwnd");
        for (n, o) in &results {
            println!(
                "{:<22} {:>9.3} {:>12.1}ms {:>12.1}ms {:>8}",
                n,
                o.link_utilisation(cap),
                o.mean_queue_delay_ms,
                o.max_queue_delay_ms,
                o.final_window
            );
        }

        let reno_out = results.last().unwrap().1;
        // The reference MUST bloat the buffer, or the link model is not posing the problem
        // this test exists to pose. This is the negative control on the SCENARIO.
        assert!(
            reno_out.max_queue_delay_ms > 100.0,
            "the reference never bloated the queue ({:.1}ms) -- the link is not a bufferbloat \
             scenario and no conclusion may be drawn from it",
            reno_out.max_queue_delay_ms
        );

        // ── THE ADVERSE FINDING, PINNED SO IT CANNOT BE QUIETLY FORGOTTEN ──────────────────
        //
        // The first version of this test asserted that EVERY YeAH variant beats the reference
        // on queue delay. It FAILED, and it was right to. On this link only Legacy does.
        // Canonical and LineRate bloat the buffer to 3960 ms -- indistinguishable from Reno.
        //
        // The mechanism is arithmetic, not mystery. The link drains 10 segments per round;
        // MAX_WINDOW is 16 (yeah.rs:44). A ceiling ABOVE the link's per-round capacity never
        // binds, so the window grows until the buffer is full, exactly as Reno does. Legacy
        // converged to 8 segments -- below capacity -- and therefore could not bloat.
        //
        // So the window ceiling is a bufferbloat defence only while MAX_WINDOW <= the link's
        // bandwidth-delay product. That is a REAL LIMITATION of the shipped constant, not a
        // property of the link model, and the general law behind it is proved for all inputs
        // in `D:/Lean/proofs/Proofs/LinkSim.lean::a_window_within_capacity_never_grows_the_queue`.
        //
        // The assertion below therefore encodes what is TRUE and understood, rather than what
        // was hoped for: a controller that settles at or below capacity does not bloat, and
        // one that settles above it does. Weakening this to `assert!(true)` or deleting it
        // would destroy the only record that the claim has a boundary.
        let cap_segments = cap / SEG;
        for (n, o) in results.iter() {
            if o.peak_window <= cap_segments {
                assert!(
                    o.max_queue_delay_ms < reno_out.max_queue_delay_ms,
                    "{n} never exceeded {} segments (<= capacity {cap_segments}) yet still bloated: \
                     {:.1}ms vs reference {:.1}ms -- the capacity law is violated",
                    o.peak_window,
                    o.max_queue_delay_ms,
                    reno_out.max_queue_delay_ms
                );
            }
        }
        // And the finding itself, asserted so a future change that FIXES it makes this test
        // fail loudly and demand its own removal -- which is the correct way for a pinned
        // limitation to expire.
        let bloaters: Vec<&String> = results
            .iter()
            .filter(|(_, o)| o.peak_window > cap_segments && o.max_queue_delay_ms > 1000.0)
            .map(|(n, _)| n)
            .collect();
        assert!(
            !bloaters.is_empty(),
            "no profile overshot capacity any more -- MAX_WINDOW may now adapt to the BDP. \
             If that is intended, this pinned limitation is obsolete and should be replaced \
             by an assertion that NO profile bloats."
        );
    }

    /// MEASURED — the speed half, on a WELL-MANAGED link where there is no bloat to avoid.
    ///
    /// This is the test that can embarrass us, which is why it is here. With a small buffer the
    /// bufferbloat advantage disappears and only the window ceiling remains. If MAX_WINDOW=16
    /// costs throughput, it shows up here as utilisation below the reference's.
    #[test]
    fn the_window_ceiling_is_measured_against_a_small_buffer_link() {
        let rounds = 2000u64;
        // 10 segments/round capacity, 20ms one-way, only 2 rounds of buffer.
        let mk = || Link::new(10 * SEG, 20.0, 2 * 10 * SEG);
        let cap = mk().capacity_per_round;

        let mut l = mk();
        let mut s = yeah_udp(YeahProfile::LineRate);
        let yeah = run(&mut s, &mut l, rounds);
        let mut l2 = mk();
        let mut reno = RenoRef { cwnd: 1 };
        let r = run(&mut reno, &mut l2, rounds);

        println!("\n=== MEASURED on a WELL-MANAGED link (2-round buffer) ===");
        println!(
            "YeAH-UDP/LineRate  util {:.3}  mean qdelay {:.1}ms  cwnd {}",
            yeah.link_utilisation(cap),
            yeah.mean_queue_delay_ms,
            yeah.final_window
        );
        println!(
            "Reno (reference)   util {:.3}  mean qdelay {:.1}ms  cwnd {}",
            r.link_utilisation(cap),
            r.mean_queue_delay_ms,
            r.final_window
        );
        // NEGATIVE CONTROL on the scenario: the link must actually be able to be saturated,
        // or a utilisation comparison is meaningless.
        assert!(
            r.link_utilisation(cap) > 0.5,
            "the reference could not saturate the link ({:.3}) -- scenario is not a speed test",
            r.link_utilisation(cap)
        );
        // NOTE: deliberately NO assertion that YeAH wins here. This test exists to REPORT a
        // number that may be unfavourable. Asserting a win would be tuning the spec to the
        // answer we want, which is the exact failure this whole session is built to avoid.
    }

    /// MEASURED — IS LEGACY ACTUALLY BETTER, OR WAS IT LUCKY?
    ///
    /// Legacy held the queue at 24 ms on a 10-segment-per-round link because it converged to 8
    /// segments, BELOW capacity. That is a property of the link that was chosen, not of the
    /// controller. This sweeps capacity from 2 to 20 segments per round and reports where each
    /// profile bloats -- which settles the question with data instead of loyalty.
    ///
    /// It also checks LinkSim.lean::a_sender_within_capacity_never_bloats against the REAL
    /// controller at every capacity: a peak window at or below capacity must show no standing
    /// queue. If the real controller ever violated that, the Lean model would not describe it
    /// and every conclusion drawn from the model would be void.
    #[test]
    fn a_capacity_sweep_shows_where_each_profile_bloats() {
        let rounds = 2000u64;
        println!("\n=== CAPACITY SWEEP: where does each profile bloat? ===");
        println!("{:<11} {:>4} {:>6} {:>12} {:>7}", "profile", "cap", "peak", "max qdelay", "util");
        let mut legacy_bloats_somewhere = false;
        let mut bloated_at_ceiling = 0u32;
        for cap_seg in [2u64, 4, 6, 8, 10, 14, 20] {
            for (name, p) in [
                ("Legacy", YeahProfile::Legacy),
                ("Canonical", YeahProfile::Canonical),
                ("LineRate", YeahProfile::LineRate),
            ] {
                let mut l = Link::new(cap_seg * SEG, 20.0, 100 * cap_seg * SEG);
                let mut s = yeah_udp(p);
                let o = run(&mut s, &mut l, rounds);
                println!(
                    "{:<11} {:>4} {:>6} {:>10.1}ms {:>7.3}",
                    name,
                    cap_seg,
                    o.peak_window,
                    o.max_queue_delay_ms,
                    o.link_utilisation(cap_seg * SEG)
                );
                if name != "Legacy" && o.max_queue_delay_ms > 1000.0 {
                    bloated_at_ceiling += 1;
                }
                if name == "Legacy" && o.max_queue_delay_ms > 100.0 {
                    legacy_bloats_somewhere = true;
                }
                // The Lean law, checked against the REAL controller at every capacity.
                if o.peak_window <= cap_seg {
                    assert!(
                        o.max_queue_delay_ms < 1.0,
                        "{name} at cap {cap_seg}: peak {} <= capacity yet queued {:.1}ms -- the \
                         Lean model does not describe the real controller",
                        o.peak_window,
                        o.max_queue_delay_ms
                    );
                }
            }
        }
        // ── THE ANSWER, AND IT REVERSED THE HYPOTHESIS ───────────────────────────────────────
        //
        // This test was written expecting Legacy's 24 ms result to be an ARTIFACT of the one
        // capacity first measured -- the guess being that Legacy simply happened to converge
        // below that link's drain rate. The sweep falsified that outright, and the original
        // assertion (`legacy_bloats_somewhere`) FAILED, which is how the guess was caught.
        //
        // Legacy holds the standing queue at EVERY capacity from 2 to 20 segments per round,
        // worst case 40 ms. Canonical and LineRate bloat to 3960 ms at every capacity where
        // MAX_WINDOW=16 exceeds the link. Legacy's peak window tracks capacity and then BACKS
        // OFF and drains; the other two run to the ceiling and sit at equilibrium, which
        // LinkSim.lean::at_capacity_the_queue_is_frozen shows preserves the queue forever.
        //
        // Legacy pays for it: ~0.888 utilisation against ~0.998. That is the real trade, and
        // both halves are now pinned so neither can be quietly lost.
        assert!(
            !legacy_bloats_somewhere,
            "Legacy bloated somewhere in the sweep. The delay reaction that made it hold the \
             queue at every capacity has regressed -- this is the check that guards it."
        );
        assert!(
            bloated_at_ceiling >= 10,
            "Canonical/LineRate no longer bloat at the ceiling ({bloated_at_ceiling} cases). If \
             a drain phase was added, this pinned limitation is obsolete and must be replaced \
             by an assertion that NO profile bloats -- do not simply delete it."
        );
    }
}
