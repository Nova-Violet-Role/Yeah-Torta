/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! surface - the Torta-side renderer seam (60C-4). NOT upstream code: this
//! module lives OUTSIDE the assimilated `gfx`/`input`/`utils` layers so the
//! upstream diff lane stays clean (see lib.rs layer map). It consumes the
//! assimilated carbonyl gfx primitives and produces an RGBA8 frame the Slint
//! shell can lift into a texture (`SharedPixelBuffer` on the host side).
//!
//! FELT-TRUTH LAW: every frame emitted here is genuinely rendered through the
//! assimilated primitives — the probe frame proves the seam, it does not fake
//! browser output.
//!
//! Integration code: AGPL/EUPL dual, (c) Saimonokuma (the #38-41 REUSE lane).

use crate::gfx::{Color, Rect, Size};
use crate::utils::log;
use crate::utils::FourBits;

/// An owned RGBA8 software surface rendered through the carbonyl gfx types.
pub struct CarbonSurface {
    size: Size,
    /// RGBA8, row-major, `width * height * 4` bytes, alpha always 0xFF
    /// (the pillar law: ZERO transparency).
    buf: Vec<u8>,
    /// 60B-3 HONEST TELEMETRY — frames genuinely finished by `render_probe_frame`.
    frames: u64,
    /// pixels written by the primitives DURING the frame being rendered right now
    px_this_frame: u64,
    /// pixels the LAST finished frame genuinely wrote (clear + lump + ember)
    last_frame_px: u64,
}

impl CarbonSurface {
    pub fn new(width: u32, height: u32) -> Self {
        let size = Size::new(width, height);
        let buf = vec![0u8; (width * height * 4) as usize];
        // Surface allocation is a rare, genuinely notable event (one per shell
        // resize), so it is the honest home for the assimilated debug lane —
        // never the per-frame path, which would drown the log.
        log::debug!(
            "CarbonSurface allocated {}x{} ({} bytes RGBA8)",
            width,
            height,
            buf.len()
        );
        Self {
            size,
            buf,
            frames: 0,
            px_this_frame: 0,
            last_frame_px: 0,
        }
    }

    pub fn width(&self) -> u32 {
        self.size.width
    }

    pub fn height(&self) -> u32 {
        self.size.height
    }

    /// The finished frame, RGBA8 row-major — ready for the host's pixel buffer.
    pub fn as_rgba(&self) -> &[u8] {
        &self.buf
    }

    /// 60B-3 — frames genuinely finished since construction (never fabricated).
    pub fn frames_rendered(&self) -> u64 {
        self.frames
    }

    /// 60B-3 — pixels the last finished frame genuinely wrote through the
    /// assimilated primitives (clear + lump facets + ember seam).
    pub fn last_frame_px(&self) -> u64 {
        self.last_frame_px
    }

    /// 60B-3 — the REAL payload each frame ships to the host, in bytes
    /// (`width * height * 4`, RGBA8 — derived from the live dims, not a constant).
    pub fn frame_bytes(&self) -> u64 {
        self.size.width as u64 * self.size.height as u64 * 4
    }

    #[inline]
    fn put(&mut self, x: i32, y: i32, c: Color) {
        if x < 0 || y < 0 || x >= self.size.width as i32 || y >= self.size.height as i32 {
            return;
        }
        let i = ((y as u32 * self.size.width + x as u32) * 4) as usize;
        self.buf[i] = c.r;
        self.buf[i + 1] = c.g;
        self.buf[i + 2] = c.b;
        self.buf[i + 3] = 0xFF;
        self.px_this_frame += 1;
    }

    pub fn clear(&mut self, c: Color) {
        for px in self.buf.chunks_exact_mut(4) {
            px[0] = c.r;
            px[1] = c.g;
            px[2] = c.b;
            px[3] = 0xFF;
        }
        self.px_this_frame += self.size.width as u64 * self.size.height as u64;
    }

    pub fn fill_rect(&mut self, rect: Rect, c: Color) {
        for y in rect.origin.y..rect.origin.y + rect.size.height as i32 {
            for x in rect.origin.x..rect.origin.x + rect.size.width as i32 {
                self.put(x, y, c);
            }
        }
    }

    /// 60C-4 probe frame — THE CHARCOAL LUMP rendered through the assimilated
    /// primitives: graphite field, a faceted piece of charcoal (the Carbon
    /// identity), an ember seam that BREATHES on `tick` — brightness only,
    /// geometry fixed. Nothing orbits, nothing spins: the old ring+glint read
    /// as a loader on-device, which violated FELT-TRUTH (nothing here loads;
    /// this is a pixel-path proof). A loader spins — an ember breathes.
    pub fn render_probe_frame(&mut self, tick: u32) {
        let graphite = Color::<u8>::new(0x14, 0x17, 0x1c);
        let coal_body = Color::<u8>::new(0x17, 0x19, 0x1c);
        let coal_lit = Color::<u8>::new(0x2a, 0x2f, 0x34);
        let coal_edge = Color::<u8>::new(0x21, 0x25, 0x29);
        let cyan = Color::<u8>::new(0x8b, 0xe9, 0xfd);

        // 60B-3 — this frame's honest pixel ledger starts at zero
        self.px_this_frame = 0;
        self.clear(graphite);

        let w = self.size.width as i32;
        let h = self.size.height as i32;

        // the lump — three axis-aligned facets clustered around the centre
        let lw = ((w as f32 * 0.52) as i32).max(4);
        let lh = ((h as f32 * 0.34) as i32).max(4);
        let lx = (w - lw) / 2;
        let ly = ((h as f32 * 0.38) as i32).max(1);
        self.fill_rect(Rect::new(lx, ly, lw as u32, lh as u32), coal_body);
        // top-left facet catching the light
        self.fill_rect(
            Rect::new(lx + lw / 8, ly - lh / 2, (lw / 2) as u32, (lh / 2) as u32),
            coal_lit,
        );
        // right shoulder facet
        self.fill_rect(
            Rect::new(lx + lw / 2, ly - lh / 4, (lw * 2 / 5) as u32, (lh / 2) as u32),
            coal_edge,
        );

        // the ember seam — a triangle wave on `tick` drives BRIGHTNESS only;
        // the seam never moves (0..=32 → dim coal-red up to bright ember).
        let ph = (tick % 64) as i32;
        let tri = (32 - (ph - 32).abs()) as u32;
        let ember = Color::<u8>::new(
            (0x9a + 2 * tri).min(0xda) as u8,
            (0x2e + tri).min(0x4e) as u8,
            0x18,
        );
        self.fill_rect(
            Rect::new(
                lx + lw / 4,
                ly + lh / 2,
                (lw / 2) as u32,
                ((lh / 6).max(2)) as u32,
            ),
            ember,
        );

        // the carbon-cyan identity tick — one static glint on the lit facet
        let gs = ((w / 32).max(2)) as u32;
        self.fill_rect(Rect::new(lx + lw / 6, ly - lh / 4, gs, gs), cyan);

        // 60B-3 — seal the ledger: the finished frame's genuine write count
        self.last_frame_px = self.px_this_frame;
        self.frames += 1;
    }

    /// Luminance of the pixel at `(x, y)`, Rec.601 weights. Out-of-range reads
    /// as black rather than panicking, so odd-sized surfaces are safe.
    fn luma_at(&self, x: u32, y: u32) -> u8 {
        if x >= self.size.width || y >= self.size.height {
            return 0;
        }
        let i = ((y * self.size.width + x) * 4) as usize;
        let (r, g, b) = (
            self.buf[i] as u32,
            self.buf[i + 1] as u32,
            self.buf[i + 2] as u32,
        );
        ((r * 77 + g * 150 + b * 29) >> 8) as u8
    }

    /// The 2×2 quadrant glyph covering cell `(cx, cy)`.
    ///
    /// This is what the assimilated [`FourBits`] exists for upstream: carbonyl
    /// is a TERMINAL browser, so a 2×2 pixel block collapses to one of exactly
    /// 16 Unicode quadrant block elements, selected by the four-bit mask
    /// `top-left << 3 | top-right << 2 | bottom-left << 1 | bottom-right`.
    ///
    /// Bit order and match totality are SETTLED IN LEAN, not sampled —
    /// `D:\Lean\proofs\Proofs\CarbonFourBits.lean` proves `new_never_panics`
    /// (the `_ => panic!("Unexpected mask value")` arm is unreachable for all
    /// 16 inputs), `mask_is_injective` and `bit_order_is_x_high_w_low`.
    pub fn quadrant_glyph_at(&self, cx: u32, cy: u32, threshold: u8) -> char {
        let (px, py) = (cx * 2, cy * 2);
        let lit = |x: u32, y: u32| self.luma_at(x, y) >= threshold;
        let bits = FourBits::new(
            lit(px, py),
            lit(px + 1, py),
            lit(px, py + 1),
            lit(px + 1, py + 1),
        );
        match bits {
            FourBits::B0000 => ' ',
            FourBits::B0001 => '\u{2597}',
            FourBits::B0010 => '\u{2596}',
            FourBits::B0011 => '\u{2584}',
            FourBits::B0100 => '\u{259D}',
            FourBits::B0101 => '\u{2590}',
            FourBits::B0110 => '\u{259E}',
            FourBits::B0111 => '\u{259F}',
            FourBits::B1000 => '\u{2598}',
            FourBits::B1001 => '\u{259A}',
            FourBits::B1010 => '\u{258C}',
            FourBits::B1011 => '\u{2599}',
            FourBits::B1100 => '\u{2580}',
            FourBits::B1101 => '\u{259C}',
            FourBits::B1110 => '\u{259B}',
            FourBits::B1111 => '\u{2588}',
        }
    }

    /// The whole surface as terminal quadrant text — one glyph per 2×2 block,
    /// rows newline-separated. The carbonyl text lane, driven by the live RGBA
    /// frame rather than by a fixture.
    pub fn to_quadrant_preview(&self, threshold: u8) -> String {
        let cols = self.size.width.div_ceil(2);
        let rows = self.size.height.div_ceil(2);
        let mut out = String::with_capacity((cols as usize + 1) * rows as usize);
        for cy in 0..rows {
            for cx in 0..cols {
                out.push(self.quadrant_glyph_at(cx, cy, threshold));
            }
            if cy + 1 < rows {
                out.push('\n');
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Instantiates `CarbonFourBits.bit_order_is_x_high_w_low` on the real
    /// renderer: each single lit pixel of a 2×2 cell must select the glyph for
    /// ITS corner. A transposition of the shifts inside `FourBits::new` shows
    /// up here as a swapped glyph, exactly as Lean mutation M52 predicted.
    #[test]
    fn quadrant_bit_order_matches_the_proved_corner_mapping() {
        let cases: [(u32, u32, char); 4] = [
            (0, 0, '\u{2598}'), // top-left  -> bit 3
            (1, 0, '\u{259D}'), // top-right -> bit 2
            (0, 1, '\u{2596}'), // bottom-left -> bit 1
            (1, 1, '\u{2597}'), // bottom-right -> bit 0
        ];
        for (x, y, want) in cases {
            let mut s = CarbonSurface::new(2, 2);
            s.clear(Color::<u8>::new(0, 0, 0));
            s.put(x as i32, y as i32, Color::<u8>::new(0xFF, 0xFF, 0xFF));
            let got = s.quadrant_glyph_at(0, 0, 0x80);
            assert_eq!(got, want, "lit pixel ({x},{y}) selected {got:?}, want {want:?}");
        }
    }

    /// Instantiates `new_never_panics` and `every_arm_is_reachable`: sweeping
    /// all 16 lit/unlit combinations of a 2×2 cell must never abort and must
    /// yield 16 DISTINCT glyphs.
    #[test]
    fn every_one_of_the_sixteen_quadrant_masks_is_reachable_and_never_panics() {
        let mut seen = std::collections::BTreeSet::new();
        for m in 0u32..16 {
            let mut s = CarbonSurface::new(2, 2);
            s.clear(Color::<u8>::new(0, 0, 0));
            let corners = [(0, 0, 3), (1, 0, 2), (0, 1, 1), (1, 1, 0)];
            for (x, y, shift) in corners {
                if m >> shift & 1 == 1 {
                    s.put(x, y, Color::<u8>::new(0xFF, 0xFF, 0xFF));
                }
            }
            seen.insert(s.quadrant_glyph_at(0, 0, 0x80));
        }
        assert_eq!(seen.len(), 16, "masks collided: {seen:?}");
    }

    /// The preview is driven by the LIVE frame, not a fixture: the probe frame
    /// must produce a non-blank preview of the right shape.
    #[test]
    fn quadrant_preview_renders_the_live_probe_frame() {
        let mut s = CarbonSurface::new(64, 32);
        s.render_probe_frame(32);
        let p = s.to_quadrant_preview(0x28);
        let lines: Vec<&str> = p.lines().collect();
        assert_eq!(lines.len(), 16, "expected height/2 rows");
        assert!(lines.iter().all(|l| l.chars().count() == 32), "expected width/2 cols");
        assert!(p.chars().any(|c| c != ' ' && c != '\n'), "preview was blank");
    }

    #[test]
    fn probe_frame_is_opaque_and_sized() {
        let mut s = CarbonSurface::new(64, 32);
        s.render_probe_frame(90);
        assert_eq!(s.as_rgba().len(), 64 * 32 * 4);
        assert!(s.as_rgba().chunks_exact(4).all(|px| px[3] == 0xFF));
    }

    #[test]
    fn telemetry_is_honest() {
        // 60B-3 — the counters report only work genuinely done: two frames
        // rendered ⇒ frames == 2; every frame clears the whole surface, so the
        // last-frame pixel ledger is at least width*height; the payload size is
        // derived from the live dims.
        let mut s = CarbonSurface::new(64, 32);
        assert_eq!(s.frames_rendered(), 0);
        assert_eq!(s.last_frame_px(), 0);
        s.render_probe_frame(0);
        s.render_probe_frame(90);
        assert_eq!(s.frames_rendered(), 2);
        assert!(s.last_frame_px() >= 64 * 32);
        assert_eq!(s.frame_bytes(), 64 * 32 * 4);
    }

    #[test]
    fn probe_frame_draws_the_lump() {
        let mut s = CarbonSurface::new(64, 64);
        s.render_probe_frame(0);
        // some pixel must carry the lit charcoal facet…
        assert!(s
            .as_rgba()
            .chunks_exact(4)
            .any(|px| px[0] == 0x2a && px[1] == 0x2f && px[2] == 0x34));
        // …and the carbon-cyan identity tick survives the redesign
        assert!(s
            .as_rgba()
            .chunks_exact(4)
            .any(|px| px[0] == 0x8b && px[1] == 0xe9 && px[2] == 0xfd));
    }

    #[test]
    fn ember_breathes_but_never_moves() {
        // FELT-TRUTH: the probe must not read as a loader. Brightness may
        // change with `tick`, but geometry must be static — the cyan identity
        // pixels sit at the SAME indices on every tick (nothing orbits).
        let cyan_at = |s: &CarbonSurface| -> Vec<usize> {
            s.as_rgba()
                .chunks_exact(4)
                .enumerate()
                .filter(|(_, px)| px[0] == 0x8b && px[1] == 0xe9 && px[2] == 0xfd)
                .map(|(i, _)| i)
                .collect()
        };
        let mut a = CarbonSurface::new(64, 64);
        a.render_probe_frame(0);
        let ca = cyan_at(&a);
        let mut b = CarbonSurface::new(64, 64);
        b.render_probe_frame(45);
        let cb = cyan_at(&b);
        assert_eq!(ca, cb);
        assert!(!ca.is_empty());
        // and the ember DOES breathe: tick 0 (dim) vs tick 32 (peak) differ
        assert_ne!(a.as_rgba(), b.as_rgba());
    }
}
