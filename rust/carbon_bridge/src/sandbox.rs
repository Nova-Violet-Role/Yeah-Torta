/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! sandbox - the Torta-side sandbox hardening seam (60E). NOT upstream code:
//! this module lives OUTSIDE the assimilated `gfx`/`input`/`utils` layers so
//! the upstream diff lane stays clean (see lib.rs layer map).
//!
//! Three heads, one law:
//!   fs jail        - every path the browser lane may touch is confined to the
//!                    jail root; a `..` escape or an outside absolute path is
//!                    REFUSED before it reaches the filesystem.
//!   permission map - per-site typed permissions, DEFAULT-DENY: an absent site
//!                    carries NO grants (the honesty law - absent is reported
//!                    as exactly that, never invented as an allow).
//!   isolation      - a host-read FACT, not a module claim: the module carries
//!                    no "isolated!" flag to set; the host reports the real
//!                    process topology (see the 60E pane line).
//!
//! Counters follow the 60B-3 law: they count only decisions genuinely taken.
//!
//! Integration code: AGPL/EUPL dual, (c) Saimonokuma (the #38-41 REUSE lane).

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// A typed per-site capability. Small on purpose - only capabilities the
/// Carbon lane genuinely mediates today earn a variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    /// Persist site data inside the jail (cookies/localStorage lane).
    Storage,
    /// Read/write the shared clipboard through the host.
    Clipboard,
    /// Open a second surface (the 60H popup lane).
    Popups,
}

/// Why the jail refused a candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailRefusal {
    /// The candidate steps out via a `..` component.
    ParentEscape,
    /// The candidate is absolute and not under the jail root.
    OutsideRoot,
}

/// 60E fs jail - confines every candidate path to the jail root.
pub struct FsJail {
    root: String,
    allowed: u64,
    refused: u64,
}

impl FsJail {
    /// A jail rooted at `root` (the REAL directory the host hands over -
    /// the module never invents one).
    pub fn new(root: &str) -> Self {
        Self {
            root: normalize(root),
            allowed: 0,
            refused: 0,
        }
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    /// Paths genuinely admitted.
    pub fn allowed(&self) -> u64 {
        self.allowed
    }

    /// Paths genuinely refused.
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// Decide one candidate. Relative candidates resolve against the jail
    /// root; any `..` component refuses BEFORE resolution (no normalization
    /// tricks), an absolute candidate must sit under the root.
    pub fn admit(&mut self, candidate: &str) -> Result<String, JailRefusal> {
        let cand = normalize(candidate);
        if cand.split('/').any(|c| c == "..") {
            self.refused += 1;
            return Err(JailRefusal::ParentEscape);
        }
        let is_absolute =
            cand.starts_with('/') || (cand.len() >= 2 && cand.as_bytes()[1] == b':');
        let full = if is_absolute {
            cand
        } else {
            format!("{}/{}", self.root, cand)
        };
        let inside = full == self.root
            || full.starts_with(&format!("{}/", self.root));
        if inside {
            self.allowed += 1;
            Ok(full)
        } else {
            self.refused += 1;
            Err(JailRefusal::OutsideRoot)
        }
    }
}

/// Backslashes fold to `/`, trailing separators drop - comparison happens on
/// one canonical shape (Windows + POSIX candidates share the jail).
fn normalize(p: &str) -> String {
    let s = p.replace('\\', "/");
    let t = s.trim_end_matches('/');
    if t.is_empty() { s } else { t.to_string() }
}

/// 60E per-site permission map - DEFAULT-DENY.
#[derive(Default)]
pub struct PermissionMap {
    grants: BTreeMap<String, BTreeSet<Permission>>,
}

impl PermissionMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sites that genuinely hold at least one grant.
    pub fn sites(&self) -> usize {
        self.grants.len()
    }

    pub fn grant(&mut self, site: &str, perm: Permission) {
        self.grants.entry(site.to_string()).or_default().insert(perm);
    }

    /// Revoking the last grant drops the site row entirely - an empty grant
    /// set and an absent site are the SAME fact (default-deny).
    pub fn revoke(&mut self, site: &str, perm: Permission) {
        if let Some(set) = self.grants.get_mut(site) {
            set.remove(&perm);
            if set.is_empty() {
                self.grants.remove(site);
            }
        }
    }

    /// DEFAULT-DENY: an absent site answers false, never a fabricated allow.
    pub fn is_granted(&self, site: &str, perm: Permission) -> bool {
        self.grants.get(site).is_some_and(|s| s.contains(&perm))
    }

    /// The surfaced rows: (site, granted set) in stable order - the pillar
    /// dash renders exactly what is genuinely held.
    pub fn rows(&self) -> impl Iterator<Item = (&str, &BTreeSet<Permission>)> {
        self.grants.iter().map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_confines_and_counts_honestly() {
        let mut j = FsJail::new("C:\\jail\\root\\");
        assert_eq!(j.root(), "C:/jail/root");
        // inside (relative) - admitted, resolved under the root
        assert_eq!(
            j.admit("site/data.db"),
            Ok("C:/jail/root/site/data.db".to_string())
        );
        // `..` escape - refused before any resolution
        assert_eq!(j.admit("a/../../etc"), Err(JailRefusal::ParentEscape));
        // absolute outside - refused
        assert_eq!(j.admit("C:/windows/system32"), Err(JailRefusal::OutsideRoot));
        // absolute inside - admitted
        assert!(j.admit("C:/jail/root/cache").is_ok());
        // sibling prefix must NOT pass as inside (root-slash boundary law)
        assert_eq!(j.admit("C:/jail/rootkit"), Err(JailRefusal::OutsideRoot));
        // 60B-3 law: counters report only decisions genuinely taken
        assert_eq!((j.allowed(), j.refused()), (2, 3));
    }

    #[test]
    fn permission_map_is_default_deny() {
        let mut m = PermissionMap::new();
        // absent site: NO grant is invented
        assert!(!m.is_granted("example.org", Permission::Storage));
        m.grant("example.org", Permission::Storage);
        assert!(m.is_granted("example.org", Permission::Storage));
        // the grant is per-capability, not per-site-wide
        assert!(!m.is_granted("example.org", Permission::Clipboard));
        assert_eq!(m.sites(), 1);
        // revoking the last grant drops the row - absent == empty (same fact)
        m.revoke("example.org", Permission::Storage);
        assert_eq!(m.sites(), 0);
        assert!(!m.is_granted("example.org", Permission::Storage));
    }
}
