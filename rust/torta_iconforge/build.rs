/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

// Compiles ui/icon.slint -> Rust (consumed by slint::include_modules!() in main.rs).
// Default host style is fine: the icon is Path-only (no widgets), so style injects nothing.
fn main() {
    slint_build::compile("ui/icon.slint").expect("SLINT icon compile failed");
}
