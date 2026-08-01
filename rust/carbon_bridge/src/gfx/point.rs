/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

use super::{Rect, Vector2};
use crate::impl_vector_overload;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point<T: Copy = i32> {
    pub x: T,
    pub y: T,
}

impl Point {
    pub fn inside(&self, rect: Rect) -> bool {
        self.x >= rect.origin.x
            && self.y >= rect.origin.y
            && self.x < rect.origin.x + rect.size.width as i32
            && self.y < rect.origin.y + rect.size.height as i32
    }
}

impl_vector_overload!(Point x y);
