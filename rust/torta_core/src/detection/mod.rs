/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **The Detection Suite** (Underground F rung) — malware-shape detectors the suffix
//! matcher cannot see, each a pure faculty emitting a [`crate::underground::Signal`] into the
//! E-rung [`crate::underground::ThreatScore`] fusion:
//!
//! - [`dga`] — algorithmically-generated label recognition (bundled n-gram table + Shannon
//!   entropy + consonant/vowel structure; fully offline, the table ships inside the `.so`).
//! - [`tunnel`] — DNS-tunneling exfil shape (per-host rolling 60s ring of TXT-answer sizes).
//! - [`beacon`] — C2 beaconing cadence (per-host inter-arrival autocorrelation) + the
//!   NXDOMAIN-burst cluster (a tunnel candidate).
//! - [`homoglyph`] — punycode/confusable brand-forgery guard (61F): a label that RENDERS as
//!   a high-value brand but is not that brand (bundled fold + skeleton tables, RFC 3492
//!   decode-only; pure — no state, no clock).
//! - [`newborn`] — newly-seen-domain probation (61F): a MODIFIER faculty — its mark never
//!   testifies alone, only beside a shape witness (the fusion enforces this).
//!
//! LAWS: detectors only RAISE score — the teeth path is untouched (a Verdict alone bites, the
//! resolver/forwarder sequestration honor stays exactly where it was). All state is RAM-only
//! rings (cap 64, the `beast_gov` RING_CAP idiom; the newborn registry rides its own
//! documented FIRST_SEEN_CAP bound) — nothing here persists, nothing here is
//! asked of a cloud (the Underground's offline law, underground.rs:6-8). Fail-open: a poisoned
//! lock means "saw nothing", never a panic on the datapath.

pub mod beacon;
pub mod dga;
pub mod homoglyph;
pub mod newborn;
pub mod tunnel;

/// Ring capacity for every per-host detector ring (the `beast_gov` RING_CAP idiom).
pub(crate) const RING_CAP: usize = 64;

/// Rolling observation window (seconds) shared by the tunnel + beacon faculties.
pub(crate) const WINDOW_SECS: u64 = 60;
