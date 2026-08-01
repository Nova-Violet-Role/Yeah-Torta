/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

#[macro_export]
macro_rules! control_flow {
    (break) => {
        std::ops::ControlFlow::Break(None)
    };
    ($expr:expr; break) => {{
        $expr;

        std::ops::ControlFlow::Break(None)
    }};
    (break $expr:expr) => {
        std::ops::ControlFlow::Break($expr.into())
    };

    (continue) => {
        std::ops::ControlFlow::Continue(None)
    };
    ($expr:expr; continue) => {{
        $expr;

        std::ops::ControlFlow::Continue(None)
    }};
    (continue $expr:expr) => {
        std::ops::ControlFlow::Continue($expr.into())
    };
}
