/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

mod dcs;
mod keyboard;
mod listen;
mod mouse;
mod parser;
// TORTA DEVIATION (#60C-2, the ONLY edit to this upstream file): tty is the Unix
// terminal seam (std::os::unix + libc) — it builds on the Android/NDK (unix) lane
// and can never build on the win32 dev host, so it is cfg(unix)-gated here.
#[cfg(unix)]
mod tty;

pub use dcs::*;
pub use keyboard::*;
pub use listen::*;
pub use mouse::*;
pub use parser::*;
#[cfg(unix)]
pub use tty::*;
