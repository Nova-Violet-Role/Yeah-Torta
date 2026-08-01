/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **C2-beacon recognition** — two per-host RAM rings:
//!
//! 1. **Cadence** — a [`VecDeque`] of arrival times; ≥ [`MIN_TICKS`] arrivals whose
//!    inter-arrival gaps hold a fixed period (within [`JITTER_TOLERANCE_SECS`], period at
//!    least [`MIN_PERIOD_SECS`]) is the implant heartbeat shape. The period floor is the FP
//!    gate: legit high-QPS traffic (a browser hammering a CDN) runs sub-second, irregular
//!    gaps — it can never look like a 60s metronome.
//! 2. **NXDOMAIN burst** — ≥ [`NX_BURST`] NXDOMAIN answers for one host inside 60s is a
//!    tunnel candidate (encoded-payload probing burns qnames), surfaced via [`nx_burst`] so
//!    the fusion wire files it under `Signal::Tunnel`.
//!
//! RAM-only, cap [`super::RING_CAP`], fail-open, offline.

use std::collections::{HashMap, VecDeque};
use std::sync::{OnceLock, RwLock};

use crate::underground::Signal;

/// Arrivals needed before a cadence can be called (the recipe's ≥6 ticks).
pub const MIN_TICKS: usize = 6;

/// Per-gap deviation from the median period tolerated (implants jitter a little).
pub const JITTER_TOLERANCE_SECS: u64 = 2;

/// Periods under this are ordinary busy traffic, never a beacon (the FP gate).
pub const MIN_PERIOD_SECS: u64 = 10;

/// NXDOMAIN answers inside 60s that make the host a tunnel candidate.
pub const NX_BURST: usize = 8;

#[derive(Debug, Default)]
struct HostRhythm {
    /// Arrival times (unix seconds), capped at [`super::RING_CAP`].
    arrivals: VecDeque<u64>,
    /// NXDOMAIN answer times, pruned to the 60s window.
    nx_times: VecDeque<u64>,
}

static RHYTHMS: OnceLock<RwLock<HashMap<String, HostRhythm>>> = OnceLock::new();

fn rhythms() -> &'static RwLock<HashMap<String, HostRhythm>> {
    RHYTHMS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Observe one arrival for `host` at `now` and judge the cadence: `Some(Signal::Beacon)` when
/// the last [`MIN_TICKS`] inter-arrival gaps hold one fixed period ≥ [`MIN_PERIOD_SECS`].
pub fn beacon_signal_at(host: &str, now: u64) -> Option<Signal> {
    let Ok(mut guard) = rhythms().write() else {
        return None;
    };
    let r = guard.entry(host.to_string()).or_default();
    r.arrivals.push_back(now);
    while r.arrivals.len() > super::RING_CAP {
        r.arrivals.pop_front();
    }
    if r.arrivals.len() < MIN_TICKS {
        return None;
    }
    // The last MIN_TICKS arrivals → MIN_TICKS-1 gaps; a metronome holds every gap at the
    // median (poor man's autocorrelation lag-1 — exact for the fixed-period shape we hunt).
    let tail: Vec<u64> = r.arrivals.iter().rev().take(MIN_TICKS).rev().copied().collect();
    drop(guard);
    cadence_verdict(&tail)
}

/// The PURE cadence verdict over an arrival tail — the single source of the beacon decision,
/// shared by the witnessing [`beacon_signal_at`] and the read-only [`beacon_peek_at`] so the two
/// can never drift into disagreeing about the same arrivals (the REUSE law).
fn cadence_verdict(tail: &[u64]) -> Option<Signal> {
    if tail.len() < MIN_TICKS {
        return None;
    }
    let mut gaps: Vec<u64> = tail.windows(2).map(|w| w[1].saturating_sub(w[0])).collect();
    if gaps.is_empty() {
        return None;
    }
    gaps.sort_unstable();
    let median = gaps[gaps.len() / 2];
    if median < MIN_PERIOD_SECS {
        return None;
    }
    let steady = gaps
        .iter()
        .all(|g| g.abs_diff(median) <= JITTER_TOLERANCE_SECS);
    steady.then_some(Signal::Beacon)
}

/// READ-ONLY cadence read — judge `host`'s ALREADY-RECORDED arrivals without contributing one.
///
/// [`beacon_signal_at`] is a WITNESS: it pushes `now` into the arrival ring before judging. An
/// observer that used it would inject a phantom arrival on every call, manufacturing exactly the
/// fixed-period cadence this detector hunts — a dashboard that refreshed on a timer could convict
/// an innocent host of beaconing at the refresh interval. This form takes a read lock, pushes
/// nothing, and evaluates the same [`cadence_verdict`] over what the engine genuinely observed.
///
/// Fail-open: a poisoned lock, or a host with no recorded arrivals, sees nothing.
pub fn beacon_peek(host: &str) -> Option<Signal> {
    let Ok(guard) = rhythms().read() else {
        return None;
    };
    let r = guard.get(host)?;
    if r.arrivals.len() < MIN_TICKS {
        return None;
    }
    let tail: Vec<u64> = r.arrivals.iter().rev().take(MIN_TICKS).rev().copied().collect();
    drop(guard);
    cadence_verdict(&tail)
}

// REMOVED: `beacon_signal(host)`, the wall-clock witnessing front door.
//
// It had no correct caller and could not acquire one — established by trying BOTH candidates and
// measuring each fail:
//   - the `underground` fusion (underground.rs:901-919) threads ONE coherent `now` through every
//     detector in a single verdict, so routing it through a clock-supplying door would give each
//     detector its own instant and introduce skew INSIDE one decision;
//   - a dashboard observer must not witness at all — this door pushes an arrival into the rhythm
//     ring, so a panel refreshing on a timer would manufacture the fixed-period cadence this very
//     detector hunts. That is why `beacon_peek` exists.
// It was also a pure alias whose doc-comment was false: it took `now: u64` and forwarded it
// unchanged while claiming to observe "at wall-clock now".
//
// The CAPABILITY is untouched and in fact wider than before: `beacon_signal_at` (witness, explicit
// clock) serves the datapath and `beacon_peek` (observer, read-only) serves the UI probe. Only a
// redundant clock-supplying alias is gone.

/// Observe one answer's rcode for `host`; true when the NXDOMAIN count inside the 60s window
/// crosses [`NX_BURST`] (tunnel candidate — the caller files `Signal::Tunnel`).
pub fn nx_burst(host: &str, qtype: u16, rcode: u8, now: u64) -> bool {
    if rcode != 3 {
        return false;
    }
    // ★ ROOT CAUSE #26 — the browser's SPECULATIVE record types must never testify.
    //
    // This ring counts NXDOMAINs for ONE host. A DNS tunnel does not re-ask the SAME fqdn: it
    // exfiltrates through a stream of DISTINCT random labels under one zone, and it carries payload in
    // TXT/NULL/CNAME/A. A BROWSER, by contrast, asks A + AAAA + HTTPS for every single navigation, so a
    // host with no AAAA and no HTTPS record earns TWO GENUINE upstream NXDOMAINs per page load — and at
    // NX_BURST=8 that is FOUR page loads before a perfectly healthy site is called a tunnel, drained to
    // zero licences and sequestrated by `underground::teeth_gate` (measured on the AVD: wildriftfire.cc,
    // lane "tunnel", 4 hits, 20 licences gone in 2 s; Socio saw the same on trends.artistgrid.cx and
    // d17vo8z6jop21h.cloudfront.net). Refusing these three qtypes removes the false positive WITHOUT
    // weakening real detection, because no tunnel encodes data in a record type that carries no payload.
    if matches!(qtype, QTYPE_AAAA | QTYPE_SVCB | QTYPE_HTTPS) {
        return false;
    }
    let Ok(mut guard) = rhythms().write() else {
        return false;
    };
    let r = guard.entry(host.to_string()).or_default();
    r.nx_times.push_back(now);
    while r.nx_times.len() > super::RING_CAP {
        r.nx_times.pop_front();
    }
    while let Some(t) = r.nx_times.front() {
        if now.saturating_sub(*t) > super::WINDOW_SECS {
            r.nx_times.pop_front();
        } else {
            break;
        }
    }
    r.nx_times.len() >= NX_BURST
}

/// AAAA — asked for EVERY navigation; absent on countless healthy IPv4-only hosts.
pub(crate) const QTYPE_AAAA: u16 = 28;
/// SVCB (RFC 9460) — speculative service binding.
pub(crate) const QTYPE_SVCB: u16 = 64;
/// HTTPS (RFC 9460) — Chrome asks it on every navigation; most origins still publish none.
pub(crate) const QTYPE_HTTPS: u16 = 65;

/// Test/scrub hook: forget every rhythm.
#[cfg(test)]
pub(crate) fn scrub_rhythms() {
    if let Ok(mut g) = rhythms().write() {
        g.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_sixty_second_cadence_fires_at_six_ticks() {
        let _g = crate::lock_detection_global();
        scrub_rhythms();
        let t0 = 1_000_000;
        for i in 0..5u64 {
            assert_eq!(beacon_signal_at("c2.example", t0 + i * 60), None, "tick {i} early-fired");
        }
        assert_eq!(beacon_signal_at("c2.example", t0 + 5 * 60), Some(Signal::Beacon));
    }

    #[test]
    fn jittered_cadence_within_tolerance_still_fires() {
        let _g = crate::lock_detection_global();
        scrub_rhythms();
        let t0 = 2_000_000;
        // 60s ± ≤2s of implant jitter.
        let mut t = t0;
        let mut last = None;
        for jitter in [60u64, 59, 61, 62, 60, 58] {
            t += jitter;
            last = beacon_signal_at("jitter.example", t);
        }
        assert_eq!(last, Some(Signal::Beacon));
    }

    #[test]
    fn fp_control_high_qps_cdn_stream_never_fires() {
        let _g = crate::lock_detection_global();
        scrub_rhythms();
        let t0 = 3_000_000;
        // A busy browser session: dozens of sub-second/irregular arrivals — the MIN_PERIOD
        // floor holds the gate no matter how regular the burst.
        let gaps = [0u64, 1, 0, 0, 2, 1, 0, 3, 0, 1, 1, 0, 2, 0, 1, 5, 1, 0, 0, 1];
        let mut t = t0;
        for g in gaps {
            t += g;
            assert_eq!(beacon_signal_at("www.google.com", t), None);
        }
    }

    /// ★ ROOT CAUSE #26 — a healthy IPv4-only site must survive unlimited browsing.
    ///
    /// Replays the EXACT field scenario measured on the AVD: Chrome asks A + AAAA + HTTPS per
    /// navigation, the origin publishes neither AAAA nor HTTPS, so each page load returns two genuine
    /// upstream NXDOMAINs. Before the fix, four loads reached NX_BURST=8 ⇒ Signal::Tunnel ⇒ lane
    /// "tunnel" ⇒ 20 licences drained ⇒ sequestrated forever by `teeth_gate` (wildriftfire.cc, and on
    /// Socio's phone trends.artistgrid.cx / d17vo8z6jop21h.cloudfront.net).
    #[test]
    fn speculative_qtype_negatives_never_convict_a_healthy_host() {
        let _g = crate::lock_detection_global();
        scrub_rhythms();
        let t0 = 5_000_000;
        // TWENTY page loads — far past NX_BURST — of the browser's speculative pair.
        for i in 0..20u64 {
            let t = t0 + i * 2;
            assert!(
                !nx_burst("wildriftfire.cc", QTYPE_AAAA, 3, t),
                "AAAA NODATA is not exfiltration (load {i})"
            );
            assert!(
                !nx_burst("wildriftfire.cc", QTYPE_HTTPS, 3, t),
                "HTTPS NODATA is not exfiltration (load {i})"
            );
        }
        // A real tunnel burns qnames on payload-carrying types — still caught, undiminished.
        for i in 0..7u64 {
            assert!(!nx_burst("exfil.example", 16, 3, t0 + i * 5));
        }
        assert!(
            nx_burst("exfil.example", 16, 3, t0 + 40),
            "TXT NXDOMAIN burst MUST still call the tunnel candidate"
        );
    }

    #[test]
    fn nx_burst_calls_the_tunnel_candidate_and_window_forgets() {
        let _g = crate::lock_detection_global();
        scrub_rhythms();
        let t0 = 4_000_000;
        // Seven NXDOMAINs in-window: quiet. The eighth calls it.
        for i in 0..7u64 {
            assert!(!nx_burst("probe.example", 1, 3, t0 + i * 5));
        }
        assert!(nx_burst("probe.example", 1, 3, t0 + 40));
        // Non-NX rcodes never count.
        assert!(!nx_burst("clean.example", 1, 0, t0));
        // 61s later the window has forgotten the burst.
        assert!(!nx_burst("probe.example", 1, 3, t0 + 40 + 61 + super::super::WINDOW_SECS));
    }
}
