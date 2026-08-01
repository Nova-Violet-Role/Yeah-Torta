// This file is part of Yeah! Tortä.
// SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
// Copyright 2026 Saimonokuma.

//! # THE GOLDEN-DIFF CORE — the instrument that decides whether a rendered pane is CORRECT
//!
//! This crate shipped with an EMPTY `lib.rs`: 0 bytes, nothing linked it, and its clean build was
//! therefore VACUOUS — green while proving nothing, because there was nothing to compile. The
//! rasterizer lived entirely in `main.rs`, reachable only by running the binary, so no test and no
//! theorem could address it.
//!
//! This module is the part that must be RIGHT: the VERDICT. Rasterizing is I/O and stays in the
//! binary; deciding whether pixels match a golden — and refusing to pass a blank frame — is a PURE
//! function over bytes, which can be tested exhaustively and PROVED for all inputs.
//!
//! ## The render failures the goal names, each with a predicate here
//!
//! * `blank where a value belongs` → [`is_blank`] — one flat colour is never a render.
//! * `missing icon` → [`DiffVerdict::size_mismatch`], including the empty-buffer case.
//! * pixel drift (clipped text, control outside parent, glyph fallback) →
//!   [`DiffVerdict::differing_pixels`], with the magnitude in `max_delta`.
//!
//! ## Why there is no tolerance window
//!
//! An instrument is GUILTY until proven able to FAIL. A golden diff that cannot go red is
//! decoration, so [`verdict_is_pass`] is deliberately unforgiving: exact equality. A tolerance
//! would also be a DATED SPEC — tuned to today's renderer and silently widening until it accepts
//! anything.

/// The outcome of comparing a rendered frame against its golden.
///
/// A struct, not a bool: when this goes red the operator must know HOW red. A bare `false` cannot
/// distinguish one antialiased edge moving from the entire pane failing to draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffVerdict {
    /// Pixels whose RGBA differs in any channel.
    pub differing_pixels: u64,
    /// Largest single-channel difference observed; 0 when the frames are identical.
    pub max_delta: u8,
    /// The frames do not share geometry — always a failure, never a "close" match.
    pub size_mismatch: bool,
    /// The RENDERED frame is a single flat colour: nothing drew.
    pub rendered_is_blank: bool,
}

/// A frame of exactly one colour never counts as a render.
///
/// This catches the quietest failure of a headless rasterizer: when the scene fails to load it
/// still emits a perfectly valid, perfectly empty PNG. If the golden were also blank, a naive diff
/// would pass. An all-transparent buffer is the same defect wearing a different alpha.
///
/// A buffer too small to hold one pixel is blank by definition — nothing is there to have drawn.
pub fn is_blank(rgba: &[u8]) -> bool {
    if rgba.len() < 4 {
        return true;
    }
    let first = &rgba[0..4];
    rgba.chunks_exact(4).all(|px| px == first)
}

/// Compare a rendered frame against its golden. PURE: no I/O, no globals, no clock.
///
/// `size_mismatch` short-circuits the pixel walk, because comparing buffers of different geometry
/// pixel-by-pixel yields a meaningless number that LOOKS like a measurement.
pub fn diff_rgba(
    rendered: &[u8],
    golden: &[u8],
    rendered_dims: (u32, u32),
    golden_dims: (u32, u32),
) -> DiffVerdict {
    let size_mismatch = rendered_dims != golden_dims || rendered.len() != golden.len();
    let rendered_is_blank = is_blank(rendered);
    if size_mismatch {
        return DiffVerdict {
            differing_pixels: 0,
            max_delta: 0,
            size_mismatch: true,
            rendered_is_blank,
        };
    }
    let mut differing_pixels = 0u64;
    let mut max_delta = 0u8;
    for (r, g) in rendered.chunks_exact(4).zip(golden.chunks_exact(4)) {
        if r != g {
            differing_pixels += 1;
            for (a, b) in r.iter().zip(g.iter()) {
                let d = a.abs_diff(*b);
                if d > max_delta {
                    max_delta = d;
                }
            }
        }
    }
    DiffVerdict {
        differing_pixels,
        max_delta,
        size_mismatch,
        rendered_is_blank,
    }
}

/// The verdict. UNFORGIVING BY DESIGN — see the module note.
///
/// A blank render FAILS EVEN IF THE GOLDEN IS ALSO BLANK. That asymmetry is deliberate: a golden
/// must not be able to license an empty frame, or the instrument could never go red for the very
/// failure it exists to catch.
pub fn verdict_is_pass(v: &DiffVerdict) -> bool {
    !v.size_mismatch && v.differing_pixels == 0 && !v.rendered_is_blank
}

/// A human-readable reason, so a red build says WHAT broke rather than only THAT it broke.
pub fn verdict_reason(v: &DiffVerdict) -> &'static str {
    if v.size_mismatch {
        "SIZE MISMATCH -- the pane rendered at different geometry than its golden (or is missing)"
    } else if v.rendered_is_blank {
        "BLANK RENDER -- a single flat colour: the scene did not draw"
    } else if v.differing_pixels > 0 {
        "PIXEL DRIFT -- the pane no longer matches its golden"
    } else {
        "PASS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two differing pixels, so the frame is genuinely drawn and the diff is meaningful.
    fn drawn(a: u8, b: u8) -> Vec<u8> {
        vec![a, a, a, 255, b, b, b, 255]
    }

    #[test]
    fn identical_drawn_frames_pass() {
        let v = diff_rgba(&drawn(1, 2), &drawn(1, 2), (2, 1), (2, 1));
        assert!(verdict_is_pass(&v));
        assert_eq!(v.differing_pixels, 0);
        assert_eq!(v.max_delta, 0);
    }

    #[test]
    fn a_single_changed_pixel_fails_loudly() {
        let v = diff_rgba(&drawn(1, 2), &drawn(1, 9), (2, 1), (2, 1));
        assert!(!verdict_is_pass(&v));
        assert_eq!(v.differing_pixels, 1);
        assert_eq!(v.max_delta, 7);
        assert_eq!(
            verdict_reason(&v),
            "PIXEL DRIFT -- the pane no longer matches its golden"
        );
    }

    #[test]
    fn a_blank_render_fails_even_against_a_blank_golden() {
        // THE NEGATIVE CONTROL FOR THE WHOLE INSTRUMENT. Without the blankness rule this is the
        // case that passes while nothing rendered at all.
        let blank = vec![0u8; 16];
        let v = diff_rgba(&blank, &blank, (2, 2), (2, 2));
        assert_eq!(v.differing_pixels, 0, "the pixels really do match");
        assert!(!verdict_is_pass(&v), "and it must STILL fail");
        assert_eq!(
            verdict_reason(&v),
            "BLANK RENDER -- a single flat colour: the scene did not draw"
        );
    }

    #[test]
    fn a_missing_pane_is_a_size_mismatch_not_a_close_match() {
        let v = diff_rgba(&[], &drawn(1, 2), (0, 0), (2, 1));
        assert!(v.size_mismatch);
        assert!(!verdict_is_pass(&v));
    }

    #[test]
    fn an_all_transparent_frame_is_blank() {
        assert!(is_blank(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(
            is_blank(&[7, 7, 7, 255, 7, 7, 7, 255]),
            "one flat colour, not merely transparent"
        );
        assert!(!is_blank(&drawn(1, 2)));
    }

    #[test]
    fn the_instrument_can_go_both_ways() {
        // Guilty until proven able to FAIL: both verdicts must be reachable.
        assert!(verdict_is_pass(&diff_rgba(
            &drawn(1, 2),
            &drawn(1, 2),
            (2, 1),
            (2, 1)
        )));
        assert!(!verdict_is_pass(&diff_rgba(
            &drawn(1, 2),
            &drawn(3, 4),
            (2, 1),
            (2, 1)
        )));
    }
}
