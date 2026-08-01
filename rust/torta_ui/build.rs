/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

// The SLINT build-pipeline: compiles ui/*.slint → Rust modules (consumed by slint::include_modules!()
// in src/lib.rs). This is what binds the .slint markup to the Rust crate — the .slint files are the
// source of truth for the UI, compiled at build time, type-checked, no runtime parsing.
fn main() {
    // Compile the root UI module. As the UI-substrate wave lands, this grows to import the 4 tabs
    // (HOME / Tortä ENGINE / DNS / QUERY) + the ||| Advanced burger, each a .slint component reading
    // its Rust pillar Object via the generated bindings.
    //
    // THE STYLE MUST BE PINNED (measured, generated main.rs): slint_build::compile() defaults to
    // the HOST OS style — on the Windows build machine that's `fluent`, whose ScrollView ships its
    // inner Flickable with `interactive: false` (desktop semantics: wheel + scrollbar only). On a
    // touch device that means every ScrollView ignores finger drags — taps land, panning is dead.
    // `material` is the Android style: drag-pan enabled, touch-sized widget metrics.
    let config = slint_build::CompilerConfiguration::new().with_style("material".into());
    slint_build::compile_with_config("ui/main.slint", config).expect("SLINT compile failed");
}
