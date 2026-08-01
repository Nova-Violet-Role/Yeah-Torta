/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **DNS-tunneling recognition** — a per-host rolling 60-second ring of answer sizes catches
//! the exfil shape the suffix matcher never can: repeated OVERSIZED TXT answers (the classic
//! iodine/dnscat payload lane), with a high-entropy leftmost label as a corroborating tell.
//! RAM-only ([`super::RING_CAP`] per host), fail-open, offline.

use std::collections::{HashMap, VecDeque};
use std::sync::{OnceLock, RwLock};

use crate::underground::Signal;

/// TXT answers at or above this wire size count as oversized (a benign SPF/DKIM TXT answer
/// rides well under; a tunnel data frame pushes the envelope every tick).
pub const TXT_OVERSIZE_BYTES: u32 = 220;

/// Oversized-TXT events within the window needed to call the shape a tunnel.
pub const TUNNEL_BURST: usize = 5;

/// One host's rolling observation ring: `(unix-seconds, answer_len, qtype)` per event, pruned
/// to the [`super::WINDOW_SECS`] window, capped at [`super::RING_CAP`].
#[derive(Debug, Default)]
pub struct TunnelRing {
    events: VecDeque<(u64, u32, u16)>,
}

impl TunnelRing {
    /// Push one event at `now`, prune the window + the cap.
    fn push(&mut self, now: u64, answer_len: u32, qtype: u16) {
        self.events.push_back((now, answer_len, qtype));
        while self.events.len() > super::RING_CAP {
            self.events.pop_front();
        }
        while let Some((t, _, _)) = self.events.front() {
            if now.saturating_sub(*t) > super::WINDOW_SECS {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Oversized-TXT events currently inside the window.
    fn oversized_txt(&self) -> usize {
        self.events
            .iter()
            .filter(|(_, len, qt)| *qt == 16 && *len >= TXT_OVERSIZE_BYTES)
            .count()
    }
}

static RINGS: OnceLock<RwLock<HashMap<String, TunnelRing>>> = OnceLock::new();

fn rings() -> &'static RwLock<HashMap<String, TunnelRing>> {
    RINGS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Observe one answered event for `host` and judge the window: `Some(Signal::Tunnel)` when the
/// oversized-TXT burst crosses [`TUNNEL_BURST`] inside 60s, corroborated (one rung earlier —
/// burst-1) when the leftmost label runs DGA-hot (a tunnel encodes payload in the qname).
/// Fail-open: a poisoned lock saw nothing.
pub fn tunnel_signal_at(host: &str, qtype: u16, answer_len: u32, now: u64) -> Option<Signal> {
    let Ok(mut guard) = rings().write() else {
        return None;
    };
    let ring = guard.entry(host.to_string()).or_default();
    ring.push(now, answer_len, qtype);
    let oversized = ring.oversized_txt();
    drop(guard);
    exfil_verdict(host, oversized)
}

// REMOVED: `tunnel_signal(host, qtype, answer_len)`, the wall-clock witnessing front door — for the
// same measured reason as its `beacon_signal` sibling. The `underground` fusion needs the explicit
// clock (`tunnel_signal_at`) so one verdict cannot skew across detectors, and an observer must not
// contribute a sample at all: this door pushes `(now, answer_len, qtype)` into the ring, so a probe
// built on it could drive a host over the burst threshold with traffic that never happened. That is
// why `tunnel_peek` exists. The capability is untouched — witness + observer, both live.

/// The PURE exfil verdict over an already-counted oversized-TXT tally — the single source of the
/// tunnel decision, shared by the witnessing [`tunnel_signal_at`] and the read-only
/// [`tunnel_peek`] so the two can never drift (the REUSE law). A DGA-hot first label lowers the
/// burst bar by one, exactly as on the witnessing path.
fn exfil_verdict(host: &str, oversized: usize) -> Option<Signal> {
    let hot_label = super::dga::dga_score(host.split('.').next().unwrap_or(""))
        >= super::dga::DGA_THRESHOLD;
    if oversized >= TUNNEL_BURST || (hot_label && oversized >= TUNNEL_BURST - 1) {
        Some(Signal::Tunnel)
    } else {
        None
    }
}

/// READ-ONLY exfil read — judge `host`'s ALREADY-RECORDED ring without contributing a sample.
///
/// [`tunnel_signal_at`] is a WITNESS: it pushes `(now, answer_len, qtype)` before judging, so an
/// observer built on it would inject a synthetic query per call and could push a host over the
/// burst threshold with traffic that never happened. This form takes a read lock, pushes nothing,
/// and runs the same [`exfil_verdict`] over what the engine genuinely observed.
///
/// Fail-open: a poisoned lock, or a host with no ring, sees nothing.
pub fn tunnel_peek(host: &str) -> Option<Signal> {
    let oversized = {
        let Ok(guard) = rings().read() else {
            return None;
        };
        guard.get(host)?.oversized_txt()
    };
    exfil_verdict(host, oversized)
}

/// Test/scrub hook: forget every ring.
#[cfg(test)]
pub(crate) fn scrub_rings() {
    if let Ok(mut g) = rings().write() {
        g.clear();
    }
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `TXT_OVERSIZE_BYTES` (= 220, detection/tunnel.rs:19) is the wire size at which
    /// a TXT answer counts as oversized. The A5 inventory found it had a NUMBER and no test
    /// naming it.
    ///
    /// The comparison is `len >= TXT_OVERSIZE_BYTES`, so the constant is a THRESHOLD and the arm
    /// that matters is the one just BELOW it: a benign SPF/DKIM answer must never accumulate
    /// toward a tunnel verdict. Rings are keyed by host, so each arm uses its own host and the
    /// test needs no global reset.
    #[test]
    fn txt_oversize_threshold_fires_at_the_bound_and_not_below() {
        let host_lo = "below.threshold.test";
        for k in 0..(TUNNEL_BURST as u64 + 3) {
            assert!(
                tunnel_signal_at(host_lo, 16, TXT_OVERSIZE_BYTES - 1, 1_700_000_000 + k).is_none(),
                "TXT answers under TXT_OVERSIZE_BYTES must never accumulate toward a tunnel call"
            );
        }
        let host_hi = "at.threshold.test";
        let mut fired = false;
        for k in 0..(TUNNEL_BURST as u64 + 3) {
            if tunnel_signal_at(host_hi, 16, TXT_OVERSIZE_BYTES, 1_700_000_000 + k).is_some() {
                fired = true;
            }
        }
        assert!(
            fired,
            "TXT answers AT TXT_OVERSIZE_BYTES must reach a tunnel verdict within the burst"
        );
        // The qtype gate: an oversized A answer is not an oversized TXT.
        let host_a = "aqtype.threshold.test";
        for k in 0..(TUNNEL_BURST as u64 + 3) {
            assert!(
                tunnel_signal_at(host_a, 1, TXT_OVERSIZE_BYTES + 500, 1_700_000_000 + k).is_none(),
                "an oversized A answer is not an oversized TXT -- the qtype gate must hold"
            );
        }
    }

    use super::*;

    #[test]
    fn oversized_txt_burst_fires_within_window() {
        let _g = crate::lock_detection_global();
        scrub_rings();
        let t0 = 1_000_000;
        // Four oversized TXT answers inside 60s: still quiet…
        for i in 0..4u64 {
            assert_eq!(tunnel_signal_at("exfil.example", 16, 400, t0 + i * 10), None);
        }
        // …the fifth crosses TUNNEL_BURST — the shape is called.
        assert_eq!(tunnel_signal_at("exfil.example", 16, 400, t0 + 45), Some(Signal::Tunnel));
    }

    #[test]
    fn window_prunes_and_a_slow_drip_never_fires() {
        let _g = crate::lock_detection_global();
        scrub_rings();
        let t0 = 2_000_000;
        // Five oversized TXT answers 61s apart — each falls out of the window before the next.
        for i in 0..5u64 {
            assert_eq!(
                tunnel_signal_at("slow.example", 16, 400, t0 + i * 61),
                None,
                "tick {i} misfired"
            );
        }
    }

    #[test]
    fn fp_control_normal_txt_and_fat_a_answers_stay_quiet() {
        let _g = crate::lock_detection_global();
        scrub_rings();
        let t0 = 3_000_000;
        // Benign SPF-sized TXT + big (CDN-ish) A answers — no oversized-TXT burst, no signal.
        for i in 0..20u64 {
            assert_eq!(tunnel_signal_at("mail.example", 16, 120, t0 + i), None);
            assert_eq!(tunnel_signal_at("cdn.example", 1, 480, t0 + i), None);
        }
    }
}
