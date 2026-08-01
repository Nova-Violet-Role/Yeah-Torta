/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

macro_rules! try_block {
    ($block:expr) => {
        (|| $block)()
    };
}

pub(crate) use try_block;
