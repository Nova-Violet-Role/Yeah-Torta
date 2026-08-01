/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! THE WARDEN DOMAIN-PATTERN ENGINE — slice 3, the clean-room reimplementation of the dnsmasq
//! firewall pattern-matching functions (the per-label glob matcher + the RFC-1123 integrity gate).
//!
//! ## CLEAN-ROOM PROVENANCE (the Genesis law — ZERO derived bytes)
//! dnsmasq-2.93 carries three firewall pattern functions whose IDEAS this module overhauls:
//!   * a per-label glob matcher with a `*` wildcard that does NOT cross a dot,
//!   * the dot-is-a-barrier law (`*.example.com` matches `api.example.com` but NOT
//!     `api.us.example.com` — the wildcard never spans a label boundary),
//!   * an RFC-1123 name/pattern VALIDATOR that bounds label length, label count, charset, and the
//!     wildcard count, and refuses an over-broad pattern (`*.com`).
//!
//! Those are the IDEAS. The dnsmasq C was **NOT read while writing this** — every line is original
//! Rust. The glob algorithm is the textbook two-pointer linear glob with one backtrack point
//! (Russ Cox, "Glob Matching Can Be Simple And Fast Too", <https://research.swtch.com/glob> — a
//! PUBLIC algorithm, NOT dnsmasq's IP). RFC-1123 is the public DNS-name standard. The GPL-2.0 corpus
//! is credited in NOTICE; no dnsmasq source byte ships.
//!
//! ## WHY (the load-bearing role — the poisoned-blocklist defense, Eidolon §2c)
//! [`validate_pattern`] is the Warden's FIRST integrity gate. Every domain rule arriving from a
//! Trust-scored blocklist passes through it BEFORE it arms (`object::WardenObject::install_domain_rules`):
//! a poisoned list that ships an over-broad `*.com` (which would NXDOMAIN every `.com` and nuke the
//! internet) or a bare TLD `com` is REJECTED here, never entering the rule-set. A validated pattern
//! that carries a `*` becomes a live glob the DNS-answer verdict walks
//! ([`super::verdict_loop::apply_dns_verdict`]); a plain domain flows to the reversed-label trie. This
//! gate is the difference between a firewall and a footgun.

use super::{normalize_rule, MAX_RULE_NAME_LEN};

/// The maximum length of one DNS label (RFC-1123).
const MAX_LABEL_LEN: usize = 63;
/// The maximum `*` wildcards permitted in ONE label (anti-overreach: a label saturated with wildcards
/// is an over-broad match).
const MAX_WILDCARDS_PER_LABEL: u8 = 2;
/// The minimum number of TRAILING LITERAL labels a pattern must end with (anti-overreach: `*.com` has
/// only one trailing literal ⇒ rejected; `*.example.com` has two ⇒ accepted).
const MIN_TRAILING_LITERAL_LABELS: usize = 2;

/// Why a domain pattern failed [`validate_pattern`] — the integrity-gate rejection cause. Carried so a
/// future slice (the `query-warden.log` rejection feed, slice 6) can surface "list X shipped N rejected
/// rules" instead of silently dropping them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MalformedPattern {
    /// The canonical form is empty (all whitespace / all empty labels).
    Empty,
    /// The total length exceeds [`MAX_RULE_NAME_LEN`] (253).
    TooLong,
    /// Fewer than two labels (a bare TLD like `com` — the over-broad nuke).
    TooFewLabels,
    /// A label is empty (a `..` in the middle — malformed).
    EmptyLabel,
    /// A label exceeds [`MAX_LABEL_LEN`] (63).
    LabelTooLong,
    /// A label carries a byte outside `[a-z0-9-*]` (after canonicalization).
    BadChar(char),
    /// A label begins or ends with a hyphen (RFC-1123).
    LeadingOrTrailingHyphen,
    /// A label carries more than [`MAX_WILDCARDS_PER_LABEL`] wildcards.
    TooManyWildcards,
    /// Fewer than [`MIN_TRAILING_LITERAL_LABELS`] trailing literal labels (e.g. `*.com`) — the
    /// over-broad pattern the gate exists to refuse.
    OverBroad,
    /// The final label is all-numeric (an IP-shaped pseudo-TLD, never a real domain).
    NumericTld,
}

/// One label of a validated pattern — its canonical (ASCII-folded) bytes + whether it carries a glob
/// wildcard. Pre-split + owned at validate time so the verdict hot path matches label-by-label with no
/// per-call allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PatternLabel {
    bytes: Box<[u8]>,
    has_wildcard: bool,
}

/// A validated, pre-split domain pattern (the output of [`validate_pattern`]). Labels are stored
/// left-to-right as authored (`*.example.com` ⇒ `["*", "example", "com"]`). [`matches`](Self::matches)
/// applies the per-label glob with the dot-is-a-barrier law.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainPattern {
    labels: Vec<PatternLabel>,
}

impl DomainPattern {
    /// True if `name` matches this pattern. The dot-is-a-barrier law: the name is split into labels,
    /// the label COUNT must equal the pattern's (so a `*.example.com` can never be tricked by a deeper
    /// `a.b.example.com`), and each label is glob-matched ([`glob_match`], ASCII case-folded). No
    /// allocation; the name is split + folded in place.
    pub fn matches(&self, name: &str) -> bool {
        let trimmed = name.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return false;
        }
        let mut name_labels = trimmed.split('.').filter(|l| !l.is_empty());
        let mut pat_labels = self.labels.iter();
        loop {
            match (name_labels.next(), pat_labels.next()) {
                (Some(nl), Some(pl)) => {
                    if !glob_match(nl.as_bytes(), &pl.bytes) {
                        return false;
                    }
                }
                // Both exhausted at the same time ⇒ equal label count ⇒ a match.
                (None, None) => return true,
                // Unequal label count ⇒ the dot-is-a-barrier law refuses the match.
                _ => return false,
            }
        }
    }

    /// True if ANY label carries a glob wildcard. The install path routes a wildcard pattern to the
    /// live glob set and a plain pattern to the reversed-label trie.
    pub fn has_any_wildcard(&self) -> bool {
        self.labels.iter().any(|l| l.has_wildcard)
    }

    /// Reconstruct the authored pattern string (labels joined left-to-right by `.`) — the reverse of
    /// [`validate_pattern`], for the settings-pane rule LIST ([`crate::warden::object::WardenObject::domain_rules`],
    /// M2). The stored label bytes are the canonical ASCII-folded charset the validate gate proved
    /// (`[a-z0-9-*]`), so the join is exact — a `*.example.com` pattern round-trips to `"*.example.com"`.
    pub fn source(&self) -> String {
        self.labels
            .iter()
            .map(|l| String::from_utf8_lossy(&l.bytes))
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// Glob-match one label `text` against one pattern label `pat`. `*` matches zero-or-more bytes WITHIN
/// the label (a label never contains a dot here — the caller split on `.`). Linear two-pointer with a
/// single backtrack point (the public Russ Cox algorithm): O(text.len() + pat.len()), no recursion, no
/// allocation, no catastrophic backtracking. ASCII case-folded (DNS is case-insensitive).
pub fn glob_match(text: &[u8], pat: &[u8]) -> bool {
    let mut t = 0usize;
    let mut p = 0usize;
    // The backtrack point: the last `*` in the pattern + the text index to resume from after it.
    let mut star_p: Option<usize> = None;
    let mut star_t = 0usize;
    while t < text.len() {
        if p < pat.len() && pat[p] == b'*' {
            // Record the star, consume it, and (greedily) try matching zero chars first.
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if p < pat.len() && pat[p].eq_ignore_ascii_case(&text[t]) {
            p += 1;
            t += 1;
        } else if let Some(sp) = star_p {
            // Mismatch under an active star: let the star absorb one more text byte and retry.
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    // Trailing pattern must be all stars to match the now-exhausted text.
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

/// THE INTEGRITY GATE — validate `input` as a domain rule pattern and return its pre-split form, or the
/// reason it was refused. Canonicalizes via [`normalize_rule`] (lowercase, drop trailing dot + empty
/// labels) then enforces RFC-1123 + the anti-overreach rules:
///   * total length `1..=253`, at least two labels;
///   * each label `1..=63` bytes, charset `[a-z0-9-*]`, no leading/trailing hyphen;
///   * at most [`MAX_WILDCARDS_PER_LABEL`] (2) wildcards per label;
///   * the final [`MIN_TRAILING_LITERAL_LABELS`] (2) labels are LITERAL (no wildcard) — so `*.com` is
///     refused but `*.example.com` is accepted;
///   * the final label is not all-numeric.
///
/// This is the poisoned-blocklist defense: a rule that fails is REJECTED at the door, never arming the
/// verdict. Ideas overhauled from dnsmasq `pattern.c` (the validators); zero derived bytes.
pub fn validate_pattern(input: &str) -> Result<DomainPattern, MalformedPattern> {
    let canon = normalize_rule(input);
    if canon.is_empty() {
        return Err(MalformedPattern::Empty);
    }
    if canon.len() > MAX_RULE_NAME_LEN {
        return Err(MalformedPattern::TooLong);
    }

    let raw_labels: Vec<&str> = canon.split('.').collect();
    if raw_labels.len() < 2 {
        return Err(MalformedPattern::TooFewLabels);
    }

    let label_count = raw_labels.len();
    let mut labels: Vec<PatternLabel> = Vec::with_capacity(label_count);
    for (i, label) in raw_labels.iter().enumerate() {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(MalformedPattern::EmptyLabel);
        }
        if bytes.len() > MAX_LABEL_LEN {
            return Err(MalformedPattern::LabelTooLong);
        }
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err(MalformedPattern::LeadingOrTrailingHyphen);
        }
        let mut wildcards: u8 = 0;
        for &b in bytes {
            match b {
                b'a'..=b'z' | b'0'..=b'9' | b'-' => {}
                b'*' => wildcards = wildcards.saturating_add(1),
                other => return Err(MalformedPattern::BadChar(other as char)),
            }
        }
        if wildcards > MAX_WILDCARDS_PER_LABEL {
            return Err(MalformedPattern::TooManyWildcards);
        }
        // Anti-overreach: the final two labels must be literal. `i` indexes the last two when
        // `i + MIN_TRAILING_LITERAL_LABELS >= label_count`.
        let is_trailing_literal_zone = i + MIN_TRAILING_LITERAL_LABELS >= label_count;
        if is_trailing_literal_zone && wildcards > 0 {
            return Err(MalformedPattern::OverBroad);
        }
        labels.push(PatternLabel {
            bytes: bytes.to_vec().into_boxed_slice(),
            has_wildcard: wildcards > 0,
        });
    }

    // The final label may not be all-numeric (an IP-shaped pseudo-TLD is never a real registrable name).
    let last = raw_labels[label_count - 1];
    if last.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MalformedPattern::NumericTld);
    }

    Ok(DomainPattern { labels })
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MAX_WILDCARDS_PER_LABEL` (= 2) and `MIN_TRAILING_LITERAL_LABELS` (= 2),
    /// warden/pattern.rs:39,42. The A5 inventory found both had NUMBERS and no test naming them.
    ///
    /// These two are ANTI-OVERREACH bounds on a firewall rule, so their failure direction is the
    /// dangerous one: too LOOSE and a single shipped rule silently blocks a whole TLD. `*.com` has
    /// one trailing literal label; accepting it would take out every `.com` the device resolves.
    ///
    /// Both arms in both directions, so each constant is pinned as a BOUND and not a constant.
    #[test]
    fn wildcard_bounds_reject_over_broad_rules_in_both_directions() {
        // MIN_TRAILING_LITERAL_LABELS: `*.com` (1 trailing literal) is REFUSED ...
        assert_eq!(
            validate_pattern("*.com"),
            Err(MalformedPattern::OverBroad),
            "a pattern with fewer than MIN_TRAILING_LITERAL_LABELS trailing literals is over-broad"
        );
        // ... while `*.example.com` (2 trailing literals) is ACCEPTED -- the bound is not a ban.
        assert!(
            validate_pattern("*.example.com").is_ok(),
            "exactly MIN_TRAILING_LITERAL_LABELS trailing literals must be accepted"
        );
        // A wildcard INSIDE the trailing zone is refused wherever it sits.
        assert_eq!(
            validate_pattern("foo.*.com"),
            Err(MalformedPattern::OverBroad),
            "a wildcard in the trailing literal zone is over-broad"
        );

        // MAX_WILDCARDS_PER_LABEL: exactly 2 in one leading label is accepted ...
        assert!(
            validate_pattern("a*b*c.example.com").is_ok(),
            "exactly MAX_WILDCARDS_PER_LABEL wildcards in a label must be accepted"
        );
        // ... 3 is refused, and with the SPECIFIC cause (not merely `is_err`).
        assert_eq!(
            validate_pattern("a*b*c*d.example.com"),
            Err(MalformedPattern::TooManyWildcards),
            "more than MAX_WILDCARDS_PER_LABEL wildcards in one label is over-broad"
        );

        // A bare TLD stays refused for its own reason -- the two rejections must not be conflated.
        assert_eq!(
            validate_pattern("com"),
            Err(MalformedPattern::TooFewLabels),
            "a bare TLD is TooFewLabels, NOT OverBroad -- distinct causes, distinct reports"
        );
    }

    use super::*;

    #[test]
    fn glob_match_cases() {
        // `*` matches zero-or-more within a single label, ASCII case-folded.
        assert!(glob_match(b"ads", b"*"), "* matches anything");
        assert!(glob_match(b"ads", b"ads"), "exact match");
        assert!(glob_match(b"ADS", b"ads"), "case-insensitive");
        assert!(glob_match(b"adserver", b"ad*"), "prefix glob");
        assert!(glob_match(b"trackad", b"*ad"), "suffix glob");
        assert!(glob_match(b"ad-tracker-net", b"ad*net"), "mid glob");
        assert!(glob_match(b"ad", b"a*d"), "star absorbs zero");
        assert!(glob_match(b"axxxd", b"a*d"), "star absorbs many");
        assert!(glob_match(b"", b""), "empty matches empty");
        assert!(glob_match(b"", b"*"), "star matches empty text");

        assert!(!glob_match(b"ads", b"adx"), "literal mismatch");
        assert!(
            !glob_match(b"ad", b"ad*x"),
            "trailing literal after star must match"
        );
        assert!(!glob_match(b"adserver", b" x*"), "wrong prefix");
        assert!(!glob_match(b"abc", b""), "non-empty text vs empty pattern");
    }

    #[test]
    fn dot_is_a_barrier() {
        // `*.example.com` matches a single-label subdomain but NOT a deeper one (the wildcard never
        // spans a dot — the load-bearing correctness invariant for a DNS firewall).
        let p = validate_pattern("*.example.com").unwrap();
        assert!(
            p.matches("api.example.com"),
            "single label under the wildcard"
        );
        assert!(p.matches("API.Example.COM"), "case-folded");
        assert!(
            !p.matches("api.us.example.com"),
            "the wildcard must NOT cross a dot"
        );
        assert!(
            !p.matches("example.com"),
            "the apex itself has no leading label"
        );
        assert!(!p.matches("api.example.org"), "different TLD");
    }

    #[test]
    fn mid_label_glob_pattern_matches() {
        // A leading-label mid-glob: `ad*.doubleclick.net`.
        let p = validate_pattern("ad*.doubleclick.net").unwrap();
        assert!(p.matches("ads.doubleclick.net"));
        assert!(p.matches("adservice.doubleclick.net"));
        assert!(
            !p.matches("img.doubleclick.net"),
            "leading label must start with 'ad'"
        );
        assert!(!p.matches("ads.doubleclick.org"));
    }

    #[test]
    fn validator_rejects_overbroad() {
        // THE POISONED-BLOCKLIST DEFENSE — the over-broad / malformed rules the gate refuses.
        assert_eq!(
            validate_pattern("*.com"),
            Err(MalformedPattern::OverBroad),
            "*.com nukes the internet"
        );
        assert_eq!(validate_pattern("*.net"), Err(MalformedPattern::OverBroad));
        assert_eq!(
            validate_pattern("com"),
            Err(MalformedPattern::TooFewLabels),
            "bare TLD"
        );
        assert_eq!(validate_pattern(""), Err(MalformedPattern::Empty));
        assert_eq!(
            validate_pattern("a.*"),
            Err(MalformedPattern::OverBroad),
            "trailing wildcard label"
        );
        assert_eq!(
            validate_pattern("ads.123"),
            Err(MalformedPattern::NumericTld),
            "all-numeric final label is IP-shaped"
        );
        assert_eq!(
            validate_pattern("-bad.example.com"),
            Err(MalformedPattern::LeadingOrTrailingHyphen)
        );
        assert_eq!(
            validate_pattern("a***b.example.com"),
            Err(MalformedPattern::TooManyWildcards),
            "more than two wildcards in a label"
        );
        // 64-char label (> 63).
        let long_label = "a".repeat(64);
        assert_eq!(
            validate_pattern(&format!("{long_label}.com")),
            Err(MalformedPattern::LabelTooLong)
        );
    }

    #[test]
    fn validator_accepts_legit_patterns() {
        // Real blocklist rules must pass cleanly.
        for good in [
            "ads.example.com",
            "doubleclick.net",
            "tracker.test",
            "*.ads.example.com",
            "ad*.doubleclick.net",
            "a-b.example.co.uk",
            "xn--80ak6aa92e.com", // punycode IDN
        ] {
            assert!(validate_pattern(good).is_ok(), "{good} should validate");
        }
        // A plain (no-wildcard) pattern reports no wildcard; a `*` one does.
        assert!(!validate_pattern("ads.example.com")
            .unwrap()
            .has_any_wildcard());
        assert!(validate_pattern("*.ads.example.com")
            .unwrap()
            .has_any_wildcard());
    }

    #[test]
    fn validated_plain_pattern_matches_exactly() {
        let p = validate_pattern("doubleclick.net").unwrap();
        assert!(p.matches("doubleclick.net"));
        assert!(
            !p.matches("ads.doubleclick.net"),
            "a plain pattern does not span labels"
        );
        assert!(!p.matches("doubleclick.org"));
    }
}
