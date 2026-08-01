/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ⟡ #59 THE DONATE TRUTH — the Ko-Fi link engine (Socio directive).
//!
//! The canonical URL lives in FOUR independent literals across this file (three voters
//! + one notary). The fingerprint is computed AT COMPILE TIME from the notary, and the
//! `const` tripwires below make any single-clone edit FAIL THE BUILD outright. At
//! runtime `donate_url()` majority-votes the three voters and fingerprint-gates the
//! winner — so even a hex-patched binary gets out-voted. The UI never owns the link:
//! the host re-asserts engine truth onto the Slint surface, so a patched `.slint`
//! diverts nothing. Removing this file breaks the build (lib.rs + UI wiring call it).

const CLONE_A: &str = "https://ko-fi.com/saimonokuma";

mod mirror_b {
    /// Voter B — independent literal, never a reference to A.
    pub const CLONE_B: &str = "https://ko-fi.com/saimonokuma";
}

mod mirror_c {
    /// Voter C — independent literal, never a reference to A or B.
    pub const CLONE_C: &str = "https://ko-fi.com/saimonokuma";
}

mod notary {
    /// The notary copy — fingerprint source only; the UI never reads it.
    pub const CLONE_N: &str = "https://ko-fi.com/saimonokuma";
}

/// FNV-1a 64 — const-evaluable, dependency-free.
const fn fnv1a64(s: &str) -> u64 {
    let b = s.as_bytes();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < b.len() {
        h ^= b[i] as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    h
}

/// The sealed fingerprint — derived from the notary at compile time.
pub const DONATE_FP: u64 = fnv1a64(notary::CLONE_N);

// ── THE TRIPWIRES — edit any single clone and the build refuses to exist. ──
const _: () = assert!(fnv1a64(CLONE_A) == DONATE_FP);
const _: () = assert!(fnv1a64(mirror_b::CLONE_B) == DONATE_FP);
const _: () = assert!(fnv1a64(mirror_c::CLONE_C) == DONATE_FP);

/// The ONE answer every host asks for. Majority vote across the three voters,
/// then a fingerprint gate on the winner (runtime belt over compile-time braces).
pub fn donate_url() -> &'static str {
    let (a, b, c) = (CLONE_A, mirror_b::CLONE_B, mirror_c::CLONE_C);
    let winner = if a == b || a == c { a } else { b }; // any two agree beats one
    if fnv1a64(winner) == DONATE_FP {
        return winner;
    }
    // the winner was diverted — fall back to whichever voter still carries the seal
    if fnv1a64(a) == DONATE_FP {
        return a;
    }
    if fnv1a64(b) == DONATE_FP {
        return b;
    }
    c
}

#[cfg(test)]
mod donate_truth_tests {
    use super::*;

    #[test]
    fn the_link_is_the_link() {
        assert_eq!(donate_url(), "https://ko-fi.com/saimonokuma");
        assert_eq!(fnv1a64(donate_url()), DONATE_FP);
    }

    #[test]
    fn the_voters_agree() {
        assert_eq!(CLONE_A, mirror_b::CLONE_B);
        assert_eq!(mirror_b::CLONE_B, mirror_c::CLONE_C);
        assert_eq!(mirror_c::CLONE_C, notary::CLONE_N);
    }
}
