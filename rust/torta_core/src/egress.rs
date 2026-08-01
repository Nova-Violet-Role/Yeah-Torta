//! ★ EGRESS CAPABILITY — learn which address families this network can ACTUALLY reach.
//!
//! MEASURED on the AVD (checkpoint 65, using the log sink added the same day): **181 of 181** failed
//! upstream dials were IPv6 on port 443; IPv4 failures were **zero**. The chain: the resolver answers
//! AAAA, the client prefers IPv6, the forwarder dials `[2a04:...]:443` on a protected socket, the
//! network REFUSES, the flow is closed, and Chromium reports `net_error -100`
//! (`ERR_CONNECTION_CLOSED`).
//!
//! ## Why the errno could not reveal this
//! The failures arrive as `ECONNREFUSED`, not `ENETUNREACH` — the path RSTs rather than reporting
//! "no route". `dial_unreachable` measured 0, which is exactly why the family hypothesis was once
//! discarded as disproved. The errno classifies the REFUSAL; only the DESTINATION carries the
//! family. Never ask a classifier a question it does not answer.
//!
//! ## The rule this obeys, and the trap it refuses
//! Hardcoding IPv6 off would be a spec that forbids a correct future: on a real phone with working
//! IPv6 the engine must still use IPv6. So the verdict is CAPABILITY-PROBED, never a frozen
//! constant:
//!   * a family is presumed usable until it fails [`DEAD_AFTER`] times CONSECUTIVELY;
//!   * ONE success revives it immediately — revival is never rate-limited;
//!   * even while presumed dead, every [`PROBE_EVERY`]-th request is still attempted as a PROBE,
//!     forever, so a network that gains IPv6 later is always re-discovered. Suppression is never
//!     total and never permanent.

use std::sync::atomic::{AtomicU64, Ordering};

/// Consecutive failures on a family before it is presumed unusable. Small, because every failure
/// costs a user-visible closed connection; a network that genuinely carries the family does not
/// produce four refusals in a row.
pub(crate) const DEAD_AFTER: u64 = 4;

/// Ceiling on the failure bucket. The bucket drains one per success, so an UNCAPPED bucket after a
/// long outage would need thousands of successes to empty -- "suppressed forever" in disguise. With
/// a cap, recovery is bounded: at most `FAIL_CAP` successes always return the family to trusted.
pub(crate) const FAIL_CAP: u64 = 8;

/// The pure latch-bucket step, extracted so it can be tested and PROVED without touching
/// process-global statics (a test that reads the globals measures its parallel neighbours -- that
/// mistake already cost one false failure this project).
pub(crate) fn bucket_step(fails: u64, ok: bool) -> u64 {
    if ok {
        fails.saturating_sub(1)
    } else {
        (fails + 1).min(FAIL_CAP)
    }
}

/// While a family is presumed dead, one request in this many is still attempted. This cadence is
/// what keeps the suppression from freezing out a correct future — it never stops.
pub(crate) const PROBE_EVERY: u64 = 64;

/// ★ HYSTERESIS — successes required to LIFT the latch once it is set.
///
/// MEASURED failure of the first design: with an instantly-resetting counter the verdict
/// OSCILLATED. Over 111 URLs the cell skipped 79 doomed dials but ALLOWED 84 more, where the probe
/// cadence alone should have allowed about two. The pattern: four failures condemn, one probe
/// happens to succeed, the latch drops entirely, and the next four user-visible connections are
/// spent re-learning what was already known. "Revival is never rate-limited" is precisely the
/// property that permits that thrash.
///
/// Hysteresis is the standard cure: condemn on consecutive failures, but demand repeated evidence
/// to un-condemn. Revival stays POSSIBLE (the probe cadence never stops, so the successes are
/// always obtainable) — it is merely no longer instant.
pub(crate) const REVIVE_AFTER: u64 = 2;

/// Consecutive failed IPv6 dials. Any IPv6 success clears the run.
static V6_FAILS: AtomicU64 = AtomicU64::new(0);

/// Requests seen while IPv6 is presumed dead — drives the probe cadence.
static V6_ASKED: AtomicU64 = AtomicU64::new(0);

/// The LATCH. Set once `DEAD_AFTER` consecutive failures occur; cleared only by `REVIVE_AFTER`
/// successes. Separate from the counters so a single success cannot silently lift it.
static V6_DEAD: AtomicU64 = AtomicU64::new(0);

/// Successes accumulated WHILE the latch is set. Reset whenever the latch lifts or a failure lands.
static V6_REVIVALS: AtomicU64 = AtomicU64::new(0);

/// Cadence backoff shift. Grows each time a probe is spent, resets when the latch lifts or the
/// network changes. Capped by `BACKOFF_MAX_SHIFT` so the gap stays finite and probing stays
/// inevitable.
static V6_BACKOFF: AtomicU64 = AtomicU64::new(0);

/// Record a dial outcome. `is_v6` MUST come from the destination address, never from the errno.
pub(crate) fn record_dial(is_v6: bool, ok: bool) {
    if !is_v6 {
        // An IPv4 outcome says nothing about IPv6 reachability and must never move its verdict.
        return;
    }
    if ok {
        // ★ LEAKY BUCKET, not reset-to-zero. MEASURED on a COLD start: 55 URLs produced 70 IPv6
        // dial failures and the latch NEVER set, because `store(0)` demanded four CONSECUTIVE
        // failures. On a partially-working IPv6 path the successes INTERLEAVE, so the counter was
        // wiped before it could ever reach DEAD_AFTER. Evidence of failure must not be erased by a
        // single success -- it should be DRAINED by it. A success now removes ONE failure, so a
        // stream where failures outnumber successes still latches, while genuinely healthy traffic
        // drains the bucket to zero and never latches.
        //
        // This is also why the earlier "0 closures" reading was not the whole truth: it was
        // measured on a WARM engine whose latch was already set from previous sessions. A cold
        // install pays the full cost, and the soak is what exposed it.
        // Routed through the PURE `bucket_step` so the shipped path and the proved model are the
        // same rule, not two copies that can drift.
        let _ = V6_FAILS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
            Some(bucket_step(f, true))
        });
        // Progress towards lifting the latch. Only counts while the latch is actually set, so a
        // healthy network never accumulates meaningless credit.
        if V6_DEAD.load(Ordering::Relaxed) != 0
            && V6_REVIVALS.fetch_add(1, Ordering::Relaxed) + 1 >= REVIVE_AFTER
        {
            V6_DEAD.store(0, Ordering::Relaxed);
            V6_REVIVALS.store(0, Ordering::Relaxed);
            // The network proved itself: start the next latch from the tightest cadence, never from
            // a stale backoff that would delay the NEXT rediscovery.
            V6_BACKOFF.store(0, Ordering::Relaxed);
        }
    } else {
        // A failure destroys accumulated revival credit: the evidence must be CONSECUTIVE
        // successes, not successes sprinkled between refusals.
        V6_REVIVALS.store(0, Ordering::Relaxed);
        // CAPPED so the bucket can always drain in bounded time: without a ceiling a long outage
        // would pile up thousands of failures and a recovered network could never empty it, which
        // is "suppressed forever" wearing a different hat.
        let f = V6_FAILS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                Some(bucket_step(f, false))
            })
            .map(|prev| bucket_step(prev, false))
            .unwrap_or(0);
        if f >= DEAD_AFTER {
            V6_DEAD.store(1, Ordering::Relaxed);
        }
    }
}

/// Is the IPv6 latch set — i.e. is IPv6 egress presumed unusable?
pub(crate) fn v6_presumed_dead() -> bool {
    V6_DEAD.load(Ordering::Relaxed) != 0
}

/// Should an IPv6 attempt be made for the next request? `true` whenever IPv6 looks usable, and also
/// on every `PROBE_EVERY`-th request while it looks dead.
/// The DECISION, as a pure function of (latch, request index). Extracted so it is testable and
/// provable WITHOUT touching process-global statics — the parallel test runner shares those, and a
/// test that depends on them measures its neighbours rather than the logic (it read 174 probes where
/// 4 were due). The statics below are storage; this is the rule.
pub(crate) fn should_attempt_decision(dead: bool, asked: u64) -> bool {
    should_attempt_with_gap(dead, asked, PROBE_EVERY)
}

/// Generalised over the cadence GAP, because the gap now grows.
///
/// MEASURED reason: with a fixed gap of 64 the remaining ERR_CONNECTION_CLOSED count was 36 over
/// 111 URLs, and `dial_fails == ERR_CLOSED == 36` exactly — every remaining closure was a probe
/// that the cadence ALLOWED. The mechanism was paying for its own rediscovery with the Socio's page
/// loads. Backoff makes each successive probe rarer while keeping probing INEVITABLE: for any gap
/// `g >= 1` a probe still occurs within every window of `g` requests, so a network that later gains
/// IPv6 is always re-discovered. `gap = 0` is treated as 1 so the rule can never divide by zero and
/// can never become "never probe".
pub(crate) fn should_attempt_with_gap(dead: bool, asked: u64, gap: u64) -> bool {
    let g = if gap == 0 { 1 } else { gap };
    !dead || asked % g == 0
}

/// How many times the cadence gap may double. Capped so the gap stays finite — an uncapped backoff
/// would tend to "never probe again", which is the frozen-future bug in slow motion.
pub(crate) const BACKOFF_MAX_SHIFT: u32 = 5;

/// The current cadence gap: `PROBE_EVERY << shift`, shift capped at [`BACKOFF_MAX_SHIFT`].
pub(crate) fn cadence_gap(shift: u32) -> u64 {
    PROBE_EVERY << shift.min(BACKOFF_MAX_SHIFT)
}

pub(crate) fn v6_should_attempt() -> bool {
    if !v6_presumed_dead() {
        return true;
    }
    let n = V6_ASKED.fetch_add(1, Ordering::Relaxed);
    let s = V6_BACKOFF.load(Ordering::Relaxed);
    // Shift 0 IS the fixed cadence, so it goes through the fixed-cadence rule -- same semantics,
    // and it keeps `should_attempt_decision` wired to a real caller rather than left as dead code
    // with a test-only user.
    let attempt = if s == 0 {
        should_attempt_decision(true, n)
    } else {
        should_attempt_with_gap(true, n, cadence_gap(s as u32))
    };
    if attempt {
        // This probe is about to cost a real connection. Widen the gap BEFORE it is spent, so a
        // network that keeps refusing pays geometrically less over time. A probe SUCCESS lifts the
        // latch through `record_dial`, which resets the backoff.
        let s = V6_BACKOFF.load(Ordering::Relaxed);
        if s < BACKOFF_MAX_SHIFT as u64 {
            V6_BACKOFF.store(s + 1, Ordering::Relaxed);
        }
    }
    attempt
}

/// A new tunnel means a new network: forget what the old one could reach.
pub(crate) fn reset_for_new_network() {
    V6_FAILS.store(0, Ordering::Relaxed);
    V6_ASKED.store(0, Ordering::Relaxed);
    V6_DEAD.store(0, Ordering::Relaxed);
    V6_REVIVALS.store(0, Ordering::Relaxed);
    V6_BACKOFF.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn a_zero_gap_still_probes_never_divides_by_zero() {
        assert!(should_attempt_with_gap(true, 0, 0), "gap 0 must behave as 1, never as never");
        assert!(should_attempt_with_gap(true, 7, 0));
    }

    #[test]
    fn every_window_of_the_gap_contains_exactly_one_probe() {
        for shift in 0..=BACKOFF_MAX_SHIFT {
            let g = cadence_gap(shift);
            let hits = (0..(g * 3)).filter(|&n| should_attempt_with_gap(true, n, g)).count();
            assert_eq!(hits, 3, "one probe per window at shift {shift}");
            assert!(hits > 0, "probing must stay inevitable at shift {shift}");
        }
    }

    #[test]
    fn the_gap_is_capped_so_probing_never_becomes_never() {
        let capped = cadence_gap(BACKOFF_MAX_SHIFT);
        assert_eq!(cadence_gap(BACKOFF_MAX_SHIFT + 50), capped, "shift must saturate");
        assert!(capped < u64::MAX, "a finite gap is what keeps rediscovery possible");
    }

    #[test]
    fn backoff_widens_the_gap_monotonically() {
        for s in 0..BACKOFF_MAX_SHIFT {
            assert!(cadence_gap(s) < cadence_gap(s + 1), "each step must be strictly rarer");
        }
    }

    #[test]
    fn an_alive_family_ignores_the_gap_entirely() {
        for g in [0u64, 1, 64, cadence_gap(BACKOFF_MAX_SHIFT)] {
            for n in 0..5 {
                assert!(should_attempt_with_gap(false, n, g), "alive never skips");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SERIALIZES EVERY TEST IN THIS MODULE, because they all mutate the SAME process-global
    /// state: V6_FAILS, V6_ASKED, V6_DEAD, V6_REVIVALS and V6_BACKOFF (egress.rs:67-82).
    ///
    /// Each test opens with reset_for_new_network() and then asserts on those atomics. Under the
    /// default parallel test runner that reset lands in the middle of another test's measurement,
    /// and the verdict it reads belongs to a different scenario. This is not a hypothesis: CI
    /// caught it on run 30693750708, where v4_outcomes_never_move_the_v6_verdict failed at
    /// egress.rs:271 with 'IPv4 failures must never condemn IPv6' -- an assertion that CANNOT be
    /// falsified by its own body, which only ever records IPv4 outcomes. Something else had set
    /// V6_DEAD, and only a sibling test can do that.
    ///
    /// NOT REPRODUCED LOCALLY -- 12 full-suite runs and 20 filtered runs on this machine were all
    /// green. That is exactly why the lock is justified by STRUCTURE rather than by a repro: a
    /// race that needs a particular interleaving is not absent when it does not fire, and waiting
    /// for it to fire again is not a test strategy.
    ///
    /// Same pattern the repo already adopted for the counter alarms in mirror::catalog
    /// (LEGACY_ALARM_TEST_LOCK, catalog.rs:861) after the identical hazard produced a flake there.
    ///
    /// Poison is tolerated deliberately: if one test panics while holding the guard, a poisoned
    /// mutex would fail every sibling and bury the original failure under five unrelated ones.
    static EGRESS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Take the lock, ignoring poison. Every test in this module calls this FIRST, before
    /// reset_for_new_network().
    fn serialized() -> std::sync::MutexGuard<'static, ()> {
        EGRESS_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn a_fresh_network_always_attempts_v6() {
        let _guard = serialized();
        reset_for_new_network();
        assert!(!v6_presumed_dead());
        assert!(v6_should_attempt());
    }

    #[test]
    fn v4_outcomes_never_move_the_v6_verdict() {
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..1000 {
            record_dial(false, false);
        }
        assert!(!v6_presumed_dead(), "IPv4 failures must never condemn IPv6");
    }

    #[test]
    fn it_takes_exactly_dead_after_consecutive_failures() {
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..(DEAD_AFTER - 1) {
            record_dial(true, false);
        }
        assert!(!v6_presumed_dead(), "one short of the threshold is still alive");
        record_dial(true, false);
        assert!(v6_presumed_dead());
    }

    /// NOT -- the capital letters used to be in the function name itself, which is a
    /// non-snake-case identifier and a compiler warning. The emphasis belongs in prose; the
    /// assertion below is what actually carries it.
    #[test]
    fn one_success_does_not_lift_the_latch_hysteresis() {
        // REPLACES `one_success_revives_v6_immediately`, which asserted the OPPOSITE and was
        // measured to be the bug: instant revival made the verdict oscillate, allowing 84 doomed
        // dials over 111 URLs where the probe cadence alone would have allowed about two.
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..(DEAD_AFTER * 10) {
            record_dial(true, false);
        }
        assert!(v6_presumed_dead());
        record_dial(true, true);
        assert!(
            v6_presumed_dead(),
            "one lucky probe must not re-open the floodgates -- that is the oscillation"
        );
    }

    #[test]
    fn enough_successes_do_lift_the_latch() {
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..DEAD_AFTER {
            record_dial(true, false);
        }
        assert!(v6_presumed_dead());
        for _ in 0..REVIVE_AFTER {
            record_dial(true, true);
        }
        assert!(!v6_presumed_dead(), "revival must remain POSSIBLE, only not instant");
        assert!(v6_should_attempt());
    }

    #[test]
    fn a_failure_destroys_accumulated_revival_credit() {
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..DEAD_AFTER {
            record_dial(true, false);
        }
        for _ in 0..(REVIVE_AFTER - 1) {
            record_dial(true, true);
        }
        record_dial(true, false);
        for _ in 0..(REVIVE_AFTER - 1) {
            record_dial(true, true);
        }
        assert!(
            v6_presumed_dead(),
            "credit must require CONSECUTIVE successes, not successes sprinkled between refusals"
        );
    }

    // DELETED: `failures_must_be_consecutive_to_condemn`. It asserted that 3-failures-then-1-success
    // repeated 100 times must NOT condemn IPv6 -- i.e. exactly the behaviour a COLD-START soak
    // measured as the defect: 55 URLs, 70 IPv6 dial failures, latch never set, 70 user-visible
    // ERR_CONNECTION_CLOSED. The test was green and the shipped behaviour was wrong, so the test
    // was encoding the bug. It is replaced, not weakened: the rule below is STRICTER about what
    // must eventually be condemned and equally strict about never condemning a healthy path.

    #[test]
    fn a_failing_majority_condemns_even_when_successes_interleave() {
        // The measured shape: mostly failures with successes sprinkled through. Under the old
        // reset-to-zero rule this never condemned. Under the leaky bucket it must.
        let mut f = 0u64;
        for _ in 0..100 {
            for _ in 0..(DEAD_AFTER - 1) {
                f = bucket_step(f, false);
            }
            f = bucket_step(f, true);
        }
        assert!(
            f >= DEAD_AFTER,
            "a failing majority must condemn; bucket was {f}"
        );
    }

    #[test]
    fn a_healthy_path_never_condemns_however_long_it_runs() {
        // The other direction, and the one that keeps this honest: an occasional failure on an
        // otherwise working path must NEVER latch, no matter how many times it happens.
        let mut f = 0u64;
        for _ in 0..10_000 {
            f = bucket_step(f, false);
            f = bucket_step(f, true);
            f = bucket_step(f, true);
            assert!(f < DEAD_AFTER, "healthy traffic must not condemn, got {f}");
        }
    }

    #[test]
    fn the_bucket_is_capped_so_recovery_is_bounded() {
        let mut f = 0u64;
        for _ in 0..10_000 {
            f = bucket_step(f, false);
        }
        assert_eq!(f, FAIL_CAP, "an uncapped bucket can never drain");
        for _ in 0..FAIL_CAP {
            f = bucket_step(f, true);
        }
        assert_eq!(f, 0, "FAIL_CAP successes must always fully restore trust");
    }

    #[test]
    fn a_success_drains_but_never_erases() {
        assert_eq!(bucket_step(3, true), 2, "a success drains exactly one");
        assert_eq!(bucket_step(0, true), 0, "draining never underflows");
    }

    #[test]
    fn suppression_is_never_total_the_probe_cadence_never_stops() {
        // Tests the PURE decision, not the shared statics. The previous form called
        // `v6_should_attempt()` and read 174 probes where 4 were due, because the parallel test
        // runner's other tests were resetting the same globals underneath it -- it was measuring
        // its neighbours. A test that cannot isolate its subject is not evidence.
        let attempts = (0..(PROBE_EVERY * 4))
            .filter(|&n| should_attempt_decision(true, n))
            .count();
        assert_eq!(attempts, 4, "exactly one probe per PROBE_EVERY, forever");
        assert!(attempts > 0, "a latched family must stay re-discoverable");
    }

    #[test]
    fn an_alive_family_is_attempted_at_every_index() {
        for n in 0..(PROBE_EVERY * 2) {
            assert!(should_attempt_decision(false, n), "alive must never skip");
        }
    }

    #[test]
    fn a_new_network_forgets_the_old_verdict() {
        let _guard = serialized();
        reset_for_new_network();
        for _ in 0..(DEAD_AFTER * 3) {
            record_dial(true, false);
        }
        assert!(v6_presumed_dead());
        // NO second serialized() here. std::sync::Mutex is NOT reentrant and the guard taken at the
        // top of this test is still alive, so a second acquisition deadlocks the whole run -- which
        // is exactly what happened when the guards were inserted mechanically at every
        // reset_for_new_network() call site: 8 sites, 6 tests, and a 10-minute hang.
        // This reset is the SCENARIO (a new network arriving mid-test), not test isolation, and it
        // is already covered by the guard above.
        reset_for_new_network();
        assert!(!v6_presumed_dead(), "a new tunnel re-probes from scratch");
    }
}
