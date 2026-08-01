/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! The version-matched UniFFI bindgen entry (UniFFI 0.31 ships NO standalone CLI — the bindgen is a bin
//! embedded in the crate, pinned to the SAME `uniffi` version as the runtime so the generated Kotlin can
//! never drift from the scaffolding). Gated behind the `uniffi-cli` feature (Cargo.toml) so it compiles ONLY
//! on demand and clap never enters the shipped cdylib.
//!
//! Run (LIBRARY mode — reads the metadata embedded by `setup_scaffolding!` + `#[uniffi::export]`):
//!   cargo run --bin uniffi-bindgen --features uniffi-cli -- \
//!     generate --library target/release/libtorta_core.so --language kotlin --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
