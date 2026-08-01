/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

// torta_iconforge (#75) — the Tortae raster forge. A HOST build-tool that renders Slint-authored
// scenes (ui/*.slint) to raster PNG via Slint's SOFTWARE renderer, headless (a custom Platform, no
// GPU/display/backend). Born to emit the launcher mipmaps, but built SCENE-AGNOSTIC + ANIMATION-READY
// as the seed of the #17 graphics engine (per-pillar animated themes, videogame-grade visuals): the
// same forge will later render scenes at arbitrary animation ticks -> frame series / sprite sheets.
//
//   torta_iconforge forge-launcher --out-dir <res_dir>
//       Emit the whole launcher family (15 rasters) into <res_dir>/mipmap-*/ in one process.
//   torta_iconforge forge-anim --out-dir <dir> [--size px] [--frames N] [--duration-ms D] [--zoom f]
//                              [--round] [--transparent]
//       Bake an animation loop (the cake "breathes") to frame_000.png.. — the #17 sprite-baking path.
//   torta_iconforge render --scene icon --size <px> --out <file>
//                          [--on-background] [--round] [--zoom <f>] [--frame <t_secs>] [--animated]
//       One-shot render of a single scene/variant. --frame sets the animation clock (#17 hook).
use std::cell::Cell;
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use slint::platform::software_renderer::{
    MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType,
};

slint::include_modules!();

// Densities: (dir suffix, adaptive-foreground px @108dp, legacy-icon px @48dp).
const DENSITIES: &[(&str, u32, u32)] = &[
    ("mdpi", 108, 48),
    ("hdpi", 162, 72),
    ("xhdpi", 216, 96),
    ("xxhdpi", 324, 144),
    ("xxxhdpi", 432, 192),
];
// Adaptive foreground keeps the 108dp safe-zone inset (zoom 1). Legacy icons have less margin, so the
// cake is zoomed to fill; round gets a touch more margin to sit inside the inscribed circle.
const ZOOM_FOREGROUND: f32 = 1.0;
const ZOOM_LEGACY_SQUARE: f32 = 1.55;
const ZOOM_LEGACY_ROUND: f32 = 1.30;

// Headless platform with a CONTROLLABLE clock. For #75 every render is static (t=0); the shared clock
// is the #17 animation-frame hook — set it per frame to render a scene at an arbitrary animation tick.
struct ForgePlatform {
    window: Rc<MinimalSoftwareWindow>,
    clock: Rc<Cell<Duration>>,
}
impl slint::platform::Platform for ForgePlatform {
    fn create_window_adapter(
        &self,
    ) -> Result<Rc<dyn slint::platform::WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
    fn duration_since_start(&self) -> Duration {
        self.clock.get()
    }
}

// Render IconScene at `size` with the given variant params -> straight (un-associated) RGBA8 bytes.
fn rasterize(
    window: &MinimalSoftwareWindow,
    ui: &IconScene,
    size: u32,
    on_background: bool,
    round: bool,
    zoom: f32,
    animated: bool,
    tick_ms: f32,
) -> Vec<u8> {
    ui.set_on_background(on_background);
    ui.set_round(round);
    ui.set_zoom(zoom);
    ui.set_animated(animated);
    ui.set_tick_ms(tick_ms);
    window.set_size(slint::PhysicalSize::new(size, size));
    window.request_redraw();

    let mut buf =
        vec![PremultipliedRgbaColor { red: 0, green: 0, blue: 0, alpha: 0 }; (size * size) as usize];
    window.draw_if_needed(|renderer| {
        renderer.render(&mut buf, size as usize);
    });

    // premultiplied-alpha -> straight RGBA8 (the PNG alpha convention).
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for px in &buf {
        let a = px.alpha;
        let (r, g, b) = if a == 0 {
            (0u8, 0u8, 0u8)
        } else {
            let un = |c: u8| (((c as u32) * 255 + (a as u32) / 2) / (a as u32)).min(255) as u8;
            (un(px.red), un(px.green), un(px.blue))
        };
        rgba.push(r);
        rgba.push(g);
        rgba.push(b);
        rgba.push(a);
    }
    rgba
}

// #32 THE ROUND LAW — the software renderer does not clip children to a rounded parent, so a
// full-bleed scene ground escapes the legacy round circle (measured: corner alpha 255). The forge
// guarantees roundness at the buffer level instead: a circular coverage mask (radius = size/2,
// 0.5px feather) scales the straight alpha; fully-outside pixels are zeroed. Pure per-pixel
// geometry — deterministic (the bake law holds).
fn apply_round_mask(rgba: &mut [u8], size: u32) {
    let c = size as f32 / 2.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 + 0.5 - c;
            let dy = y as f32 + 0.5 - c;
            let cov = (c - (dx * dx + dy * dy).sqrt() + 0.5).clamp(0.0, 1.0);
            if cov < 1.0 {
                let i = ((y * size + x) * 4) as usize;
                if cov <= 0.0 {
                    rgba[i..i + 4].fill(0);
                } else {
                    rgba[i + 3] = (rgba[i + 3] as f32 * cov).round() as u8;
                }
            }
        }
    }
}

fn write_png(path: &Path, size: u32, rgba: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    let file = File::create(path).expect("create png");
    let mut enc = png::Encoder::new(BufWriter::new(file), size, size);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().expect("png header");
    w.write_image_data(rgba).expect("png data");
}

// The launcher family: per density, an adaptive foreground + a legacy square + a legacy round.
fn forge_launcher(out_dir: &Path, window: &MinimalSoftwareWindow, ui: &IconScene) {
    for (suffix, fg_px, legacy_px) in DENSITIES {
        let dir = out_dir.join(format!("mipmap-{suffix}"));
        write_png(
            &dir.join("ic_launcher_foreground.png"),
            *fg_px,
            &rasterize(window, ui, *fg_px, false, false, ZOOM_FOREGROUND, false, 0.0),
        );
        write_png(
            &dir.join("ic_launcher.png"),
            *legacy_px,
            &rasterize(window, ui, *legacy_px, true, false, ZOOM_LEGACY_SQUARE, false, 0.0),
        );
        write_png(
            &dir.join("ic_launcher_round.png"),
            *legacy_px,
            &rasterize(window, ui, *legacy_px, true, true, ZOOM_LEGACY_ROUND, false, 0.0),
        );
    }
    eprintln!(
        "torta_iconforge: forged {} launcher rasters into {}",
        DENSITIES.len() * 3,
        out_dir.display()
    );
}

// Bake an animation: sweep `tick-ms` across one `duration_ms` loop, emitting frame_000.png.. into
// out_dir. This is the #17 sprite/animation-baking path — the same forge, the scene driven by the
// clock instead of frozen at rest. (Also advances the platform clock so animation-tick() scenes bake.)
fn forge_anim(
    out_dir: &Path,
    window: &MinimalSoftwareWindow,
    ui: &IconScene,
    clock: &Rc<Cell<Duration>>,
    size: u32,
    frames: u32,
    duration_ms: f32,
    on_background: bool,
    round: bool,
    zoom: f32,
) {
    for i in 0..frames {
        let t_ms = if frames > 0 { (i as f32) * (duration_ms / frames as f32) } else { 0.0 };
        clock.set(Duration::from_secs_f32(t_ms / 1000.0));
        let mut rgba = rasterize(window, ui, size, on_background, round, zoom, true, t_ms);
        if round {
            apply_round_mask(&mut rgba, size);
        }
        write_png(&out_dir.join(format!("frame_{i:03}.png")), size, &rgba);
    }
    eprintln!(
        "torta_iconforge: forged {frames} animation frames ({size}x{size}, {duration_ms}ms loop) into {}",
        out_dir.display()
    );
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

// #32 THE SCENE REGISTRY — the recurrence point: adding a scene = ONE entry here + ONE component
// in ui/scenebook.slint + ONE registry row in ui/icon.slint. Nothing else moves.
const SCENES: &[&str] = &[
    "icon", "jesdict", "beast-oven", "centauri-sky", "inu-den", "masque-veil", "wheel-orbit",
    "warden-court", "underground-rain", "dango-daikazoku",
];

/// Read a PNG back as RGBA8 + dimensions. `None` when the file is absent or unreadable — a MISSING
/// golden must never be mistaken for a matching one, so callers treat `None` as a hard failure.
fn read_png(path: &Path) -> Option<(u32, u32, Vec<u8>)> {
    let file = std::fs::File::open(path).ok()?;
    let decoder = png::Decoder::new(std::io::BufReader::new(file));
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    Some((info.width, info.height, buf))
}

/// Rasterize one scene at `size` with the settings the goldens are blessed under.
///
/// Deliberately FIXED and shared by `bless` and `verify`: if the two used different settings the
/// diff would measure the settings, not the render. `--animated` is off and the clock is pinned to
/// zero so the frame is DETERMINISTIC — an animated golden would fail at random and teach everyone
/// to ignore it.
fn render_scene_for_golden(
    window: &MinimalSoftwareWindow,
    ui: &IconScene,
    clock: &Rc<Cell<Duration>>,
    scene: &str,
    size: u32,
) -> Vec<u8> {
    ui.set_scene(scene.into());
    clock.set(Duration::ZERO);
    rasterize(window, ui, size, true, false, 1.0, false, 0.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let clock = Rc::new(Cell::new(Duration::ZERO));
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(ForgePlatform {
        window: window.clone(),
        clock: clock.clone(),
    }))
    .expect("set_platform");
    let ui = IconScene::new().expect("IconScene::new");
    ui.show().expect("show");

    match args.get(1).map(|s| s.as_str()) {
        Some("forge-launcher") => {
            let out = flag(&args, "--out-dir").expect("forge-launcher needs --out-dir <res_dir>");
            forge_launcher(Path::new(&out), &window, &ui);
        }
        Some("forge-anim") => {
            let out = flag(&args, "--out-dir").expect("forge-anim needs --out-dir <dir>");
            let scene = flag(&args, "--scene").unwrap_or_else(|| "icon".into());
            assert!(
                SCENES.contains(&scene.as_str()),
                "unknown scene '{scene}' — scenes: {}", SCENES.join(", ")
            );
            ui.set_scene(scene.as_str().into());
            let size: u32 = flag(&args, "--size").and_then(|s| s.parse().ok()).unwrap_or(432);
            let frames: u32 = flag(&args, "--frames").and_then(|s| s.parse().ok()).unwrap_or(24);
            let duration_ms: f32 =
                flag(&args, "--duration-ms").and_then(|s| s.parse().ok()).unwrap_or(1000.0);
            let on_background = !args.iter().any(|a| a == "--transparent");
            let round = args.iter().any(|a| a == "--round");
            let zoom: f32 = flag(&args, "--zoom").and_then(|s| s.parse().ok()).unwrap_or(1.4);
            forge_anim(
                Path::new(&out), &window, &ui, &clock, size, frames, duration_ms, on_background, round, zoom,
            );
        }
        Some("render") => {
            let scene = flag(&args, "--scene").unwrap_or_else(|| "icon".into());
            assert!(
                SCENES.contains(&scene.as_str()),
                "unknown scene '{scene}' — scenes: {}", SCENES.join(", ")
            );
            ui.set_scene(scene.as_str().into());
            let size: u32 = flag(&args, "--size").and_then(|s| s.parse().ok()).unwrap_or(432);
            let out = flag(&args, "--out").unwrap_or_else(|| "icon.png".into());
            let on_background = args.iter().any(|a| a == "--on-background");
            let round = args.iter().any(|a| a == "--round");
            let zoom: f32 = flag(&args, "--zoom").and_then(|s| s.parse().ok()).unwrap_or(1.0);
            let animated = args.iter().any(|a| a == "--animated");
            let t_secs = flag(&args, "--frame").and_then(|s| s.parse::<f32>().ok()).unwrap_or(0.0);
            clock.set(Duration::from_secs_f32(t_secs)); // #17 animation-tick hook (runtime-style scenes)
            write_png(
                Path::new(&out),
                size,
                &{
                    let mut rgba = rasterize(&window, &ui, size, on_background, round, zoom, animated, t_secs * 1000.0);
                    if round { apply_round_mask(&mut rgba, size); }
                    rgba
                },
            );
            eprintln!("torta_iconforge: rendered '{scene}' -> {out} ({size}x{size})");
        }
        // ★ BLESS — write the goldens. Goldens change only DELIBERATELY, which is why this is a
        // SEPARATE subcommand and never a fallback inside `verify`: a verify that silently writes a
        // missing golden can never fail, and an instrument that cannot fail is decoration.
        Some("bless") => {
            let dir = flag(&args, "--goldens").unwrap_or_else(|| "goldens".into());
            let size: u32 = flag(&args, "--size").and_then(|s| s.parse().ok()).unwrap_or(128);
            std::fs::create_dir_all(&dir).expect("create goldens dir");
            for scene in SCENES {
                let rgba = render_scene_for_golden(&window, &ui, &clock, scene, size);
                let path = Path::new(&dir).join(format!("{scene}.png"));
                // A blank golden would license a blank render forever. Refuse to bless one.
                assert!(
                    !torta_iconforge::is_blank(&rgba),
                    "REFUSING to bless a BLANK golden for '{scene}' -- the scene did not draw"
                );
                write_png(&path, size, &rgba);
                eprintln!("blessed {scene} -> {}", path.display());
            }
        }
        // ★ VERIFY — rasterize every scene headless and diff against the goldens IN THE REPO.
        // Exits NON-ZERO on any failure, so a render regression breaks the build loudly.
        Some("verify") => {
            let dir = flag(&args, "--goldens").unwrap_or_else(|| "goldens".into());
            let size: u32 = flag(&args, "--size").and_then(|s| s.parse().ok()).unwrap_or(128);
            let mut failed = 0usize;
            for scene in SCENES {
                let rgba = render_scene_for_golden(&window, &ui, &clock, scene, size);
                let path = Path::new(&dir).join(format!("{scene}.png"));
                match read_png(&path) {
                    // A MISSING golden is a FAILURE, never a pass. This is the case a lazy harness
                    // treats as "nothing to compare" and reports green.
                    None => {
                        eprintln!("FAIL {scene}: golden MISSING or unreadable at {}", path.display());
                        failed += 1;
                    }
                    Some((gw, gh, golden)) => {
                        let v = torta_iconforge::diff_rgba(&rgba, &golden, (size, size), (gw, gh));
                        if torta_iconforge::verdict_is_pass(&v) {
                            eprintln!("ok   {scene}");
                        } else {
                            eprintln!(
                                "FAIL {scene}: {} (differing_pixels={} max_delta={})",
                                torta_iconforge::verdict_reason(&v),
                                v.differing_pixels,
                                v.max_delta
                            );
                            failed += 1;
                        }
                    }
                }
            }
            eprintln!("golden-diff: {} scene(s), {failed} failed", SCENES.len());
            if failed > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "usage:\n  torta_iconforge forge-launcher --out-dir <res_dir>\n  torta_iconforge forge-anim --out-dir <dir> [--scene <scene>] [--size px] [--frames N] [--duration-ms D] [--zoom f] [--round] [--transparent]\n  torta_iconforge render --scene <scene> --size <px> --out <file> [--on-background] [--round] [--zoom f] [--frame t] [--animated]\n  torta_iconforge bless  --goldens <dir> [--size px]\n  torta_iconforge verify --goldens <dir> [--size px]"
            );
            std::process::exit(2);
        }
    }
}
