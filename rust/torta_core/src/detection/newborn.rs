/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **Newly-seen-domain probation** (61F) — a RAM-only first-seen registry: a host inside
//! [`PROBATION_SECS`] of its first witness carries the newborn mark. LAWS: this is a
//! MODIFIER faculty — it NEVER testifies alone (the fusion only lets it join beside a
//! SHAPE witness; "newly seen" beside nothing is first-install noise, not evidence). The
//! registry feeds on every scored row (the tunnel-ring RAM-only-per-host precedent —
//! nothing here reaches the ledger), bounded at [`FIRST_SEEN_CAP`] with oldest-first
//! eviction (an evicted long-known host can re-register as newborn — noise the
//! never-alone law already absorbs). Fail-open: a poisoned lock saw nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::{OnceLock, RwLock};

/// Seconds a first-witnessed host stays in probation.
pub const PROBATION_SECS: u64 = 600;

/// Registry bound — oldest registration evicted first past this.
pub const FIRST_SEEN_CAP: usize = 4096;

/// First-witness registry: birth second per host + insertion order for eviction.
#[derive(Debug, Default)]
struct Registry {
    born: HashMap<String, u64>,
    order: VecDeque<String>,
}

static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();

fn registry() -> &'static RwLock<Registry> {
    REGISTRY.get_or_init(|| RwLock::new(Registry::default()))
}

/// Observe `host` at `now` and judge probation: `true` while within [`PROBATION_SECS`] of
/// its FIRST witness (the first sight itself is newborn by definition). Records every
/// unseen host (benign included — RAM detector state, never ledger rows). Fail-open: a
/// poisoned lock saw nothing.
pub fn newborn_at(host: &str, now: u64) -> bool {
    let Ok(mut g) = registry().write() else {
        return false;
    };
    if let Some(&born) = g.born.get(host) {
        return now.saturating_sub(born) <= PROBATION_SECS;
    }
    if g.born.len() >= FIRST_SEEN_CAP {
        if let Some(oldest) = g.order.pop_front() {
            g.born.remove(&oldest);
        }
    }
    g.born.insert(host.to_string(), now);
    g.order.push_back(host.to_string());
    true
}

// REMOVED: `newborn(host)`, the wall-clock witnessing front door — same measured reason as its
// `beacon_signal` / `tunnel_signal` siblings. The `underground` fusion needs the explicit clock
// (`newborn_at`) so one verdict cannot skew across detectors, and an observer must not register at
// all: this door INSERTS the host and, at `FIRST_SEEN_CAP`, EVICTS the oldest registration — so a
// probe built on it would destroy the very detector state it meant to report. That is why
// `newborn_peek` exists. The capability is untouched — witness + observer, both live.

/// READ-ONLY probation read at `now` — judge `host` WITHOUT registering it.
///
/// Distinct from [`newborn_at`] in BOTH effect and meaning, and both differences are load-bearing:
///   - EFFECT: takes only a read lock. It never inserts, and therefore never evicts — where
///     `newborn_at` at [`FIRST_SEEN_CAP`] pops the oldest registration, so an observer built on the
///     witnessing form would silently destroy the very detector state it meant to report on.
///   - MEANING: an UNSEEN host reads `false`, not `true`. `newborn_at` answers `true` because the
///     caller IS the first witness; an observer is not a witness, so "never seen" is an absence of
///     evidence and must never be reported as a positive signal.
///
/// Fail-open: a poisoned lock saw nothing.
pub fn newborn_peek_at(host: &str, now: u64) -> bool {
    let Ok(g) = registry().read() else {
        return false;
    };
    match g.born.get(host) {
        Some(&born) => now.saturating_sub(born) <= PROBATION_SECS,
        None => false,
    }
}

/// The read-only front door — [`newborn_peek_at`] at wall-clock now. This is what a dashboard
/// probe uses, so opening a panel can never perturb what the engine has learned.
pub fn newborn_peek(host: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    newborn_peek_at(host, now)
}

/// Test/scrub hook: forget every registration.
#[cfg(test)]
pub(crate) fn scrub_registry() {
    if let Ok(mut g) = registry().write() {
        g.born.clear();
        g.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sight_probation_then_maturity() {
        let _g = crate::lock_detection_global();
        scrub_registry();
        let t0 = 1_000_000;
        assert!(newborn_at("fresh.example", t0), "first sight IS newborn");
        assert!(newborn_at("fresh.example", t0 + PROBATION_SECS - 1));
        assert!(!newborn_at("fresh.example", t0 + PROBATION_SECS + 1), "matured");
        assert!(!newborn_at("fresh.example", t0 + 10 * PROBATION_SECS), "stays matured");
    }

    #[test]
    fn cap_evicts_oldest_registration_only() {
        let _g = crate::lock_detection_global();
        scrub_registry();
        let t0 = 2_000_000;
        for i in 0..FIRST_SEEN_CAP {
            newborn_at(&format!("host-{i}.example"), t0);
        }
        // One more arrival evicts host-0 — the survivor stays matured, the evictee
        // re-registers (the documented noise the never-alone fusion law absorbs).
        newborn_at("overflow.example", t0 + 1);
        let later = t0 + PROBATION_SECS + 10;
        assert!(!newborn_at("host-1.example", later), "survivor matured");
        assert!(newborn_at("host-0.example", later), "evictee re-registers as newborn");
    }
}
