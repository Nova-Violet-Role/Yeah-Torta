/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! carbon_bridge - the Torta Carbon Browser bridge crate.
//!
//! Assimilated pure-Rust layers from carbonyl (Fathy Boundjadj, BSD-3-Clause);
//! upstream license notice retained verbatim in `LICENSE.carbonyl.md`.
//! Files under `src/gfx*` are upstream-verbatim (Iconforge-style assimilation,
//! SOCIO DIRECTIVE 2026-07-22); Torta-side shim code lives OUTSIDE the
//! assimilated modules so upstream diffs stay clean.
//!
//! Layer map:
//!   gfx    - color / point / rect / size / vector primitives (dependency-free)
//!   input  - dcs / keyboard / listen / mouse / parser / tty (dependency-free;
//!            control_flow! lives in input/dcs, exported at crate root)
//!   utils  - four_bits / try_block / log (private, mirrors upstream; chrono-backed log)
//!
//! Torta shim lane (NOT upstream):
//!   surface - 60C-4 renderer seam: RGBA8 software surface rendered through
//!             the assimilated gfx primitives, lifted by the Slint host
//!   route   - 60D socket-layer routing seam: Warden > Underground > Beast QoS
//!             precedence, decisions fed by the host off the LIVE engine
//!   sandbox - 60E hardening seam: fs jail (root confinement) + per-site
//!             DEFAULT-DENY permission map; isolation is a host-read fact
//!   specials - 60F userscript + WebExtension engine: Tampermonkey-class
//!              header law (@match / @run-at, GM_* surface) + labeled MV2/MV3
//!              manifest sniff; bay counters grow only on real decisions

pub mod engine;
pub mod gfx;
pub mod input;
pub mod route;
pub mod sandbox;
pub mod specials;
pub mod surface;

mod utils;
