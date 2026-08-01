/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! route - the Torta-side socket-layer routing seam (60D). NOT upstream code:
//! this module lives OUTSIDE the assimilated `gfx`/`input`/`utils` layers so
//! the upstream diff lane stays clean (see lib.rs layer map). Every socket the
//! Carbon Browser will ever open must pass THIS seam before it touches the
//! network — the routing law: Warden firewall outranks Underground reputation
//! outranks Beast QoS classing; a denied socket NEVER reaches a Beast lane.
//!
//! FELT-TRUTH LAW: the probe decides through inputs the HOST read off the LIVE
//! engine (Beast QoS phase, Underground reputation, Warden firewall) — it
//! proves the seam, it does not fake browser traffic. Counters follow the
//! 60B-3 law: they count only decisions genuinely taken.
//!
//! Integration code: AGPL/EUPL dual, (c) Saimonokuma (the #38-41 REUSE lane).

/// Why a probe socket was refused a lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The Warden firewall layer said no (precedence 1 — outranks everything).
    Firewall,
    /// The Underground reputation verdict said no (precedence 2).
    Reputation,
}

/// The socket-layer decision for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneDecision {
    /// Routed onto the Torta stack, carrying the Beast QoS class it rides.
    Routed { qos_class: u8 },
    /// Refused — the reason names the layer that vetoed it.
    Denied { reason: DenyReason },
}

/// 60D probe — the socket-layer seam gatekeeper with honest counters.
pub struct SocketProbe {
    routed: u64,
    denied: u64,
}

impl Default for SocketProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketProbe {
    pub fn new() -> Self {
        Self {
            routed: 0,
            denied: 0,
        }
    }

    /// Decisions that genuinely landed on a Beast lane.
    pub fn routed(&self) -> u64 {
        self.routed
    }

    /// Decisions genuinely vetoed by a routing layer.
    pub fn denied(&self) -> u64 {
        self.denied
    }

    /// Decide one candidate through the routing law. Precedence: Warden
    /// firewall > Underground reputation > Beast QoS classing — a denied
    /// socket NEVER carries a QoS class.
    pub fn decide(
        &mut self,
        firewall_deny: bool,
        reputation_deny: bool,
        qos_class: u8,
    ) -> LaneDecision {
        let d = if firewall_deny {
            LaneDecision::Denied {
                reason: DenyReason::Firewall,
            }
        } else if reputation_deny {
            LaneDecision::Denied {
                reason: DenyReason::Reputation,
            }
        } else {
            LaneDecision::Routed { qos_class }
        };
        match d {
            LaneDecision::Routed { .. } => self.routed += 1,
            LaneDecision::Denied { .. } => self.denied += 1,
        }
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_outranks_reputation() {
        // the routing law: when BOTH layers object, the firewall names the veto
        let mut p = SocketProbe::new();
        assert_eq!(
            p.decide(true, true, 2),
            LaneDecision::Denied {
                reason: DenyReason::Firewall
            }
        );
        assert_eq!(
            p.decide(false, true, 2),
            LaneDecision::Denied {
                reason: DenyReason::Reputation
            }
        );
    }

    #[test]
    fn clean_candidate_rides_the_qos_lane() {
        let mut p = SocketProbe::new();
        assert_eq!(p.decide(false, false, 3), LaneDecision::Routed { qos_class: 3 });
    }

    #[test]
    fn counters_are_honest() {
        // 60B-3 law: counters report only decisions genuinely taken
        let mut p = SocketProbe::new();
        assert_eq!((p.routed(), p.denied()), (0, 0));
        p.decide(false, false, 1);
        p.decide(true, false, 1);
        p.decide(false, true, 1);
        assert_eq!((p.routed(), p.denied()), (1, 2));
    }
}
