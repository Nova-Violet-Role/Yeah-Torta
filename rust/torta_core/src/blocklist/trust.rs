/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P8 Wave A2 — provenance / trust store for the blocklist matcher.
//!
//! This module carries WHERE a blocked domain came from and HOW MUCH that source is trusted —
//! **alongside** the blocked set, never inside it. The load-bearing invariant of the whole P8
//! blocklist design is that `Matcher::finalize()`'s fingerprint is the SET oracle ONLY: it folds the
//! canonical terminal domains and NOTHING else. Source tags, trust weights and labels all live here
//! (and in the per-`Node` [`SourceMask`] bitset over in `blocklist.rs`), so two installs of the SAME
//! blocked set with DIFFERENT provenance still produce the SAME fingerprint. That is what keeps the
//! later C2 Centauri parity gate (which compares the SET) intact.
//!
//! Storage is a plain `u32` bitset per terminal node — 32 source slots, no new crate, no struct in the
//! trie. A `SourceRegistry` maps a caller's opaque `source_id` to a stable bit index and remembers the
//! human label + trust weight for that source. A3 will add a `BlockAction` enum here and B1 the trust
//! scoring; both ride alongside the set, exactly like this does.

use std::collections::HashMap;

/// A per-terminal provenance bitset: bit `b` set ⇒ the source mapped to bit `b` armed this domain.
/// A domain corroborated by N sources has N bits set. `0` = anonymous / legacy (the source-less path),
/// which is also bit 0's reserved meaning. Plain `u32` keeps the trie node tiny and dependency-free.
pub type SourceMask = u32;

/// Reserved source id for the legacy / anonymous text path (`compile_and_install_text`, artifact
/// decode, raw `insert`). It always maps to bit 0, so an untagged install records mask `1 << 0`'s slot
/// only when explicitly tagged — the source-LESS [`insert`](super::Matcher::insert) sets NO bit at all
/// (mask stays `0`) and stays byte-identical to pre-A2.
pub const ANON_SOURCE_ID: u32 = 0;

/// The number of distinct source slots a `u32` mask can hold (bits 0..=31).
pub const MAX_SOURCE_BITS: u32 = 32;

/// The shared "overflow" bit: any source assigned a bit index ≥ this value is clamped here, so the
/// 33rd+ distinct source still records *some* corroboration without panicking or silently aliasing a
/// real slot. Documented cap: provenance beyond 31 distinct sources collapses onto bit 31.
pub const OVERFLOW_BIT: u32 = 31;

/// Map a source id's assigned bit index to its mask. Indices ≥ [`MAX_SOURCE_BITS`] clamp to the shared
/// [`OVERFLOW_BIT`] so the shift can never be UB (`1u32 << 32` is undefined) and never aliases bit 0.
#[inline]
pub fn bit_to_mask(bit: u32) -> SourceMask {
    let bit = if bit >= MAX_SOURCE_BITS {
        OVERFLOW_BIT
    } else {
        bit
    };
    1u32 << bit
}

/// What we remember about one blocklist source — its opaque id, a 0..=100 trust weight, a label, and
/// (P8 Wave B1) the per-source signals the trust SCORE reads: a signature gate, a curated reputation,
/// and first/last seen ages. Trust/label/score-inputs ride here ALONGSIDE the set; they NEVER enter
/// the fingerprint. These are INPUTS to the score, never OUTPUTS folded back into the SET hash.
///
/// A2 scaffolding: `id`/`trust`/`label` are stored by A2 and READ by A3 (`BlockAction`) / B1 (trust
/// scoring) and the unit tests. B1 adds `signed`/`reputation`/`first_seen_epoch_days`/
/// `last_seen_epoch_days`. The attr keeps the production (non-test) cdylib warning-free without dropping
/// the API — the SAME convention `Matcher::to_artifact` uses.
#[derive(Clone, Debug)]
pub struct SourceMeta {
    /// The caller's opaque source identifier (stable across installs of the same source).
    pub id: u32,
    /// Operator/base trust weight 0..=100 (the A2 weight; B1's score blends it with `reputation`).
    pub trust: u8,
    /// Human-readable label, e.g. "StevenBlack hosts" or "user pick".
    pub label: Box<str>,
    /// B1 — signature-verified source? This is the LOAD-BEARING security gate: when `true` the trust
    /// CEILING is lifted to the signed band; when `false` the score is capped BELOW any signed source.
    /// The FNV fingerprint is identity/dedup ONLY (non-crypto, forgeable) and NEVER lifts this — only a
    /// real signature (C3/minisign sets `signed = true`) does. B1 stores+reads it; default `false`.
    pub signed: bool,
    /// B1 — curated source reputation 0..=100, DISTINCT from the operator `trust` weight. The score
    /// blends the two; default 0.
    pub reputation: u8,
    /// B1 — first-seen age in epoch-days (0 = unknown). Stored for provenance; recency uses `last_seen`.
    pub first_seen_epoch_days: u32,
    /// B1 — last-seen age in epoch-days (0 = unknown ⇒ neutral recency). Older lists decay gently.
    pub last_seen_epoch_days: u32,
}

impl SourceMeta {
    /// A2 constructor — id + operator trust weight + label. B1 score-inputs default to neutral
    /// (`signed = false`, `reputation = 0`, ages `0`/unknown). Existing A2 call sites are unchanged.
    pub fn new(id: u32, trust: u8, label: impl Into<Box<str>>) -> Self {
        Self {
            id,
            trust,
            label: label.into(),
            signed: false,
            reputation: 0,
            first_seen_epoch_days: 0,
            last_seen_epoch_days: 0,
        }
    }

    /// B1 — set the signature gate (the trust CEILING control). Builder-style, additive.
    pub fn with_signed(mut self, signed: bool) -> Self {
        self.signed = signed;
        self
    }

    /// B1 — set the curated reputation 0..=100 (clamped). Builder-style, additive.
    pub fn with_reputation(mut self, reputation: u8) -> Self {
        self.reputation = reputation.min(100);
        self
    }

    /// B1 — set the first/last seen ages in epoch-days (0 = unknown). Builder-style, additive.
    pub fn with_seen(mut self, first_seen_epoch_days: u32, last_seen_epoch_days: u32) -> Self {
        self.first_seen_epoch_days = first_seen_epoch_days;
        self.last_seen_epoch_days = last_seen_epoch_days;
        self
    }
}

/// Maps caller `source_id`s to stable mask bit indices and remembers each source's [`SourceMeta`].
///
/// The registry is the provenance store: it lives ALONGSIDE the matcher (the matcher's trie only holds
/// the compact [`SourceMask`] bitset per terminal). Bit assignment is first-come stable — the same
/// `source_id` always gets the same bit within one registry. Id [`ANON_SOURCE_ID`] is reserved to bit
/// 0. Beyond 32 distinct sources, new ids clamp to [`OVERFLOW_BIT`] (documented saturation, never UB,
/// never bit-0 aliasing).
/// A2 scaffolding: `bit_for`/`mask_for` are used by `install_with_source` today; the metadata/query
/// helpers (`register`/`meta`/`mask_has_source`/`corroboration`/…) are consumed by A3/B1 and the tests.
/// The attr keeps the non-test cdylib warning-free without dropping the API (the `to_artifact` pattern).
#[derive(Default)]
pub struct SourceRegistry {
    /// source_id → assigned bit index.
    id_to_bit: HashMap<u32, u32>,
    /// source_id → metadata (trust, label, B1 score-inputs). Provenance, NOT part of the set/fingerprint.
    metas: HashMap<u32, SourceMeta>,
    /// Next free bit to hand out (0 is pre-claimed by the anonymous/legacy source).
    next_bit: u32,
    /// B1 dedup index: installed-list FINGERPRINT → the source_ids that produced THAT identical set.
    /// The fingerprint is consumed here as an IDENTITY/DEDUP key ONLY (it is never produced FROM trust —
    /// strictly one-directional, the A2 contract). Two sources with the SAME fingerprint are the SAME
    /// list ⇒ they collapse into one bucket ⇒ list trust = MAX over the bucket, never summed.
    fp_to_ids: HashMap<u64, Vec<u32>>,
    /// B1 inverse index: source_id → the fingerprint of the list it last produced (as reported by
    /// `Matcher::fingerprint` / `installed_fingerprint`). Pure metadata, alongside the set.
    set_fp: HashMap<u32, u64>,
}

impl SourceRegistry {
    /// A fresh registry with [`ANON_SOURCE_ID`] pre-bound to bit 0 (trust 0, label "anonymous").
    pub fn new() -> Self {
        let mut reg = SourceRegistry {
            id_to_bit: HashMap::new(),
            metas: HashMap::new(),
            next_bit: 0,
            fp_to_ids: HashMap::new(),
            set_fp: HashMap::new(),
        };
        // Reserve bit 0 for the anonymous/legacy source so a real source never lands on it.
        reg.id_to_bit.insert(ANON_SOURCE_ID, 0);
        reg.metas.insert(
            ANON_SOURCE_ID,
            SourceMeta::new(ANON_SOURCE_ID, 0, "anonymous"),
        );
        reg.next_bit = 1;
        reg
    }

    /// Get the bit index for `source_id`, assigning the next free bit on first sight. Beyond
    /// [`MAX_SOURCE_BITS`] distinct sources, new ids clamp to [`OVERFLOW_BIT`] (documented cap).
    pub fn bit_for(&mut self, source_id: u32) -> u32 {
        if let Some(&bit) = self.id_to_bit.get(&source_id) {
            return bit;
        }
        let bit = if self.next_bit >= MAX_SOURCE_BITS {
            OVERFLOW_BIT
        } else {
            let b = self.next_bit;
            self.next_bit += 1;
            b
        };
        self.id_to_bit.insert(source_id, bit);
        bit
    }

    /// The mask (`1 << bit`) for `source_id`, assigning a bit on first sight. This is what
    /// `insert_with_source` ORs into a terminal node.
    pub fn mask_for(&mut self, source_id: u32) -> SourceMask {
        bit_to_mask(self.bit_for(source_id))
    }

    /// Record/replace the metadata (trust, label) for a source. Ensures the id also has a bit.
    pub fn register(&mut self, meta: SourceMeta) {
        let _ = self.bit_for(meta.id);
        self.metas.insert(meta.id, meta);
    }

    /// Look up a source's metadata, if registered.
    pub fn meta(&self, source_id: u32) -> Option<&SourceMeta> {
        self.metas.get(&source_id)
    }

    /// Every registered source's metadata, for the SOURCES panel.
    ///
    /// Iteration order is unspecified (a `HashMap`), so a caller that renders this must sort —
    /// otherwise the panel's row order changes between reads and looks like data churn when
    /// nothing has changed.
    pub fn metas(&self) -> impl Iterator<Item = &SourceMeta> {
        self.metas.values()
    }

    /// The bit index assigned to `source_id`, if it has been seen.
    pub fn assigned_bit(&self, source_id: u32) -> Option<u32> {
        self.id_to_bit.get(&source_id).copied()
    }

    /// True if `mask` has the bit for `source_id` set (i.e. that source armed the domain).
    pub fn mask_has_source(&self, mask: SourceMask, source_id: u32) -> bool {
        match self.assigned_bit(source_id) {
            Some(bit) => mask & bit_to_mask(bit) != 0,
            None => false,
        }
    }

    /// How many distinct sources corroborate a mask (popcount).
    pub fn corroboration(mask: SourceMask) -> u32 {
        mask.count_ones()
    }

    /// Every registered `source_id`. The read seam behind `blocklist::domain_provenance`: a panel
    /// that must report WHICH sources tagged a domain has to be able to enumerate them, and the
    /// registry previously offered only point lookups. Iteration order is unspecified (HashMap) —
    /// callers must fold with an order-independent operation (max, popcount), never index.
    pub fn source_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.id_to_bit.keys().copied()
    }

    // ---- P8 Wave B1: set-fingerprint dedup index (same fp ⇒ same list ⇒ trust = max) ----

    /// Record that `source_id` produced a list with installed-set fingerprint `fp`. Idempotent: a
    /// source re-noted with the SAME fp does NOT duplicate in the bucket (so importing one list twice
    /// never inflates the bucket or double-counts its trust). If the source previously reported a
    /// DIFFERENT fp, it is migrated out of the old bucket so the index stays accurate.
    ///
    /// The fingerprint is taken as an opaque IDENTITY/DEDUP key only; nothing here is ever written back
    /// into `finalize()`'s SET hash — the dependency is strictly fingerprint → trust, never the reverse.
    pub fn note_fingerprint(&mut self, source_id: u32, fp: u64) {
        // Ensure the source has a bit so corroboration/meta stay consistent with its provenance.
        let _ = self.bit_for(source_id);
        if let Some(&prev) = self.set_fp.get(&source_id) {
            if prev == fp {
                return; // already in the right bucket — idempotent, no double-count
            }
            // Migrate out of the stale bucket.
            if let Some(ids) = self.fp_to_ids.get_mut(&prev) {
                ids.retain(|&id| id != source_id);
                if ids.is_empty() {
                    self.fp_to_ids.remove(&prev);
                }
            }
        }
        self.set_fp.insert(source_id, fp);
        let bucket = self.fp_to_ids.entry(fp).or_default();
        if !bucket.contains(&source_id) {
            bucket.push(source_id);
        }
    }

    /// The source_ids that produced the list with fingerprint `fp` (the dedup bucket), if any.
    pub fn ids_for_fingerprint(&self, fp: u64) -> Option<&[u32]> {
        self.fp_to_ids.get(&fp).map(|v| v.as_slice())
    }

    /// The fingerprint last reported by `source_id`, if noted.
    pub fn fingerprint_of(&self, source_id: u32) -> Option<u64> {
        self.set_fp.get(&source_id).copied()
    }
}

// ---- P8 Wave B1: the per-source trust SCORE (pure, integer, deterministic; no new crate) ----
//
// The score reads ONLY trust.rs metadata + the SourceMask popcount (the SEPARATE provenance read path
// over in blocklist.rs via `source_mask`/`walk_terminals_with_sources`). It NEVER touches
// `Node.terminal`, `walk_terminals`, or `fnv1a`, so it can NEVER perturb the SET fingerprint. The
// fingerprint flows INTO the score as the dedup key; it is never produced FROM the score.

/// The trust ceiling an UNSIGNED source can reach. Held STRICTLY below `SIGNED_FLOOR` so an unsigned
/// source — no matter how high its reputation/overlap/age — can NEVER reach a signed source's band.
/// Only a real signature (`SourceMeta::signed`, set by C3/minisign) lifts the ceiling. The FNV
/// fingerprint is identity/dedup only and never raises this.
pub const UNSIGNED_CEILING: u8 = 60;

/// The minimum score a signed source achieves once it has any base trust — strictly ABOVE
/// `UNSIGNED_CEILING`, so the signed/unsigned bands cannot overlap. (A signed source with zero base
/// still benefits from the lifted ceiling; this floor documents the separation the tests assert.)
pub const SIGNED_FLOOR: u8 = UNSIGNED_CEILING + 1;

/// Each independent corroborating source (beyond the first) adds this many points to the score…
pub const CORR_STEP: u16 = 6;
/// …up to this cap, so corroboration is bounded and monotone-nondecreasing (diminishing returns; a
/// flood of sources cannot run the score away).
pub const CORR_CAP: u16 = 24;

/// Recency decay is applied as a fixed-point factor in `RECENCY_MIN_PCT..=100` percent (no float dep).
/// A list last-seen `RECENCY_FULL_DAYS` ago or fresher keeps 100%; older lists decay linearly down to
/// `RECENCY_MIN_PCT`. `last_seen == 0` (unknown) is treated as the neutral 100%.
pub const RECENCY_MIN_PCT: u16 = 70;
/// Days within which a list keeps full (100%) recency weight.
pub const RECENCY_FULL_DAYS: u32 = 90;
/// Days beyond `RECENCY_FULL_DAYS` over which recency decays from 100% to `RECENCY_MIN_PCT`.
pub const RECENCY_DECAY_DAYS: u32 = 365;

/// Fixed-point recency factor in percent (`RECENCY_MIN_PCT..=100`) for a list last seen `last_seen`
/// epoch-days ago, evaluated at `now_days`. `last_seen == 0` (unknown) or `now < last_seen` ⇒ neutral
/// 100. Within `RECENCY_FULL_DAYS` ⇒ 100; then linear decay to `RECENCY_MIN_PCT`, clamped there.
pub fn recency_pct(last_seen_epoch_days: u32, now_days: u32) -> u16 {
    if last_seen_epoch_days == 0 || now_days <= last_seen_epoch_days {
        return 100; // unknown or fresh ⇒ neutral
    }
    let age = now_days - last_seen_epoch_days;
    if age <= RECENCY_FULL_DAYS {
        return 100;
    }
    let over = age - RECENCY_FULL_DAYS;
    if over >= RECENCY_DECAY_DAYS {
        return RECENCY_MIN_PCT;
    }
    // Linear: 100 - (100 - RECENCY_MIN_PCT) * over / RECENCY_DECAY_DAYS.
    let span = 100 - RECENCY_MIN_PCT; // points lost at full decay
    let lost = (span as u32 * over) / RECENCY_DECAY_DAYS; // integer, monotone-nondecreasing in `over`
    (100 - lost as u16).max(RECENCY_MIN_PCT)
}

/// Compute the trust score `0..=100` for ONE source, given the corroboration mask of the terminal(s)
/// it armed and a clock (`now_days`, epoch-days; pass `0` to disable recency / treat all as fresh).
///
/// Shape (all integer / fixed-point, deterministic):
///   base    = (trust + reputation) / 2                         — operator weight blended with rep
///   recency = base scaled by `recency_pct(last_seen, now)/100` — older lists trusted slightly less
///   corr    = min((popcount - 1) * CORR_STEP, CORR_CAP)        — bounded, monotone corroboration bonus
///   raw     = recency + corr                                   — saturating in 0..=100
///   then BAND-SEPARATE on the signature gate:
///     signed   ⇒ score = clamp(raw, SIGNED_FLOOR, 100)         — lifted INTO the signed band
///     unsigned ⇒ score = min(raw, UNSIGNED_CEILING)            — capped BELOW the signed band
///
/// The band depends ONLY on this source's own `signed` flag — never on the fingerprint, never on other
/// sources. Because `SIGNED_FLOOR > UNSIGNED_CEILING`, EVERY signed score is strictly greater than
/// EVERY unsigned score, regardless of reputation/overlap/age. This is the LOAD-BEARING security
/// boundary: the FNV fingerprint (non-crypto, forgeable) can never move a source between bands — only a
/// real signature (`SourceMeta::signed`, set by C3/minisign) does.
pub fn trust_score(
    reg: &SourceRegistry,
    source_id: u32,
    active_mask: SourceMask,
    now_days: u32,
) -> u8 {
    let meta = match reg.meta(source_id) {
        Some(m) => m,
        None => return 0, // unknown source ⇒ no trust
    };

    // BASE: operator weight blended with curated reputation (both 0..=100).
    let base = (meta.trust as u16 + meta.reputation as u16) / 2;

    // RECENCY: gentle fixed-point decay; unknown/fresh ⇒ 100% (neutral).
    let recency = (base * recency_pct(meta.last_seen_epoch_days, now_days)) / 100;

    // CORROBORATION: each distinct ARMING source beyond the first adds a bounded, capped bonus. Uses the
    // SourceMask popcount, so identical-fp re-imports of one list (same bit) do NOT inflate it.
    let corr = SourceRegistry::corroboration(active_mask);
    let corr_bonus = ((corr.saturating_sub(1)) as u16 * CORR_STEP).min(CORR_CAP);

    let raw = (recency + corr_bonus).min(100) as u8;

    // BAND SEPARATION: the security boundary. A signed source is lifted into `SIGNED_FLOOR..=100`; an
    // unsigned one is capped at `UNSIGNED_CEILING`. SIGNED_FLOOR > UNSIGNED_CEILING ⇒ the bands never
    // overlap, so unsigned < signed ALWAYS. Only a real signature crosses the gate; the fingerprint
    // never does.
    if meta.signed {
        raw.max(SIGNED_FLOOR) // already ≤ 100 by construction
    } else {
        raw.min(UNSIGNED_CEILING)
    }
}

/// The trust score for a whole LIST identified by its set fingerprint `fp`. Two sources with the SAME
/// fingerprint are the SAME list ⇒ they collapse into one dedup bucket ⇒ this returns the MAX
/// `trust_score` over the bucket — never the SUM, so importing one list once or twice yields the SAME
/// value. Returns `0` if no source has produced `fp`.
///
/// Corroboration still rides on the `active_mask` popcount (distinct ARMING bits), so identical-fp
/// re-imports do not inflate corroboration either — only genuinely distinct sources raise it.
pub fn list_trust(reg: &SourceRegistry, fp: u64, active_mask: SourceMask, now_days: u32) -> u8 {
    match reg.ids_for_fingerprint(fp) {
        Some(ids) => ids
            .iter()
            .map(|&id| trust_score(reg, id, active_mask, now_days))
            .max()
            .unwrap_or(0),
        None => 0,
    }
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MAX_SOURCE_BITS` (= 32) and `OVERFLOW_BIT` (= 31), blocklist/trust.rs:36,40.
    /// The A5 inventory found both had NUMBERS and no test naming them.
    ///
    /// This clamp is not a capacity choice, it is a SOUNDNESS one: `1u32 << 32` is undefined
    /// behaviour in C and a panic in debug Rust, so an unclamped shift turns "the 33rd blocklist
    /// source" into a crash on the DNS hot path. The universal claim is therefore stronger than a
    /// bound -- for EVERY u32 whatsoever, `bit_to_mask` returns, and returns a single real bit.
    #[test]
    fn bit_to_mask_never_shifts_out_of_range_for_any_u32() {
        // Below the ceiling: the mask is exactly that bit, and nothing else.
        for bit in 0..MAX_SOURCE_BITS {
            let m = bit_to_mask(bit);
            assert_eq!(m, 1u32 << bit, "bit {bit} must map to its own slot");
            assert_eq!(m.count_ones(), 1, "a source mask is exactly one bit");
        }
        // At and above the ceiling: everything collapses onto OVERFLOW_BIT, and NOTHING panics.
        for bit in [
            MAX_SOURCE_BITS,
            MAX_SOURCE_BITS + 1,
            63,
            64,
            255,
            u32::MAX / 2,
            u32::MAX - 1,
            u32::MAX,
        ] {
            let m = bit_to_mask(bit);
            assert_eq!(
                m,
                1u32 << OVERFLOW_BIT,
                "bit {bit} is past MAX_SOURCE_BITS and must clamp to the shared overflow slot"
            );
        }
        // The universal shape, over a dense sweep: always exactly one bit, never zero.
        for bit in 0..1024u32 {
            let m = bit_to_mask(bit);
            assert_eq!(
                m.count_ones(),
                1,
                "bit {bit}: a mask must always be exactly one real slot, never 0 and never wrapped"
            );
        }
        // The overflow slot is a REAL slot, not a sentinel: it aliases bit 31 deliberately, and
        // that aliasing is the documented cost of going past 31 distinct sources.
        assert_eq!(
            bit_to_mask(OVERFLOW_BIT),
            bit_to_mask(MAX_SOURCE_BITS + 9_000),
            "past the ceiling, provenance collapses onto bit 31 by design"
        );
    }

    use super::*;

    #[test]
    fn anon_is_bit_zero_and_real_sources_never_alias_it() {
        let mut reg = SourceRegistry::new();
        assert_eq!(reg.bit_for(ANON_SOURCE_ID), 0);
        // First real source must NOT be bit 0.
        let b = reg.bit_for(42);
        assert_ne!(b, 0);
        assert_eq!(b, 1);
        // Stable: same id → same bit.
        assert_eq!(reg.bit_for(42), 1);
        // A different id → a different bit.
        assert_eq!(reg.bit_for(7), 2);
    }

    #[test]
    fn mask_for_sets_the_expected_bit() {
        let mut reg = SourceRegistry::new();
        assert_eq!(reg.mask_for(100), 1u32 << 1); // first real source → bit 1
        assert_eq!(reg.mask_for(200), 1u32 << 2);
        assert_eq!(reg.mask_for(100), 1u32 << 1); // stable
    }

    #[test]
    fn corroboration_counts_distinct_sources() {
        let mut reg = SourceRegistry::new();
        let m = reg.mask_for(1) | reg.mask_for(2) | reg.mask_for(3);
        assert_eq!(SourceRegistry::corroboration(m), 3);
        assert!(reg.mask_has_source(m, 1));
        assert!(reg.mask_has_source(m, 2));
        assert!(!reg.mask_has_source(m, 999)); // never registered
    }

    #[test]
    fn overflow_clamps_and_never_panics_or_aliases_bit_zero() {
        let mut reg = SourceRegistry::new();
        // Hand out far more than 32 distinct sources; none must panic, none may land on bit 0.
        for id in 1..=100u32 {
            let bit = reg.bit_for(id);
            assert!(bit <= OVERFLOW_BIT);
            assert_ne!(bit, 0, "real source {id} aliased the anonymous bit 0");
        }
        // The 33rd+ source clamps to the overflow bit.
        assert_eq!(reg.bit_for(40), OVERFLOW_BIT);
        // bit_to_mask never produces UB for an out-of-range index.
        assert_eq!(bit_to_mask(99), 1u32 << OVERFLOW_BIT);
    }

    #[test]
    fn register_stores_trust_and_label() {
        let mut reg = SourceRegistry::new();
        reg.register(SourceMeta::new(5, 90, "StevenBlack hosts"));
        let m = reg.meta(5).expect("registered");
        assert_eq!(m.trust, 90);
        assert_eq!(&*m.label, "StevenBlack hosts");
        assert!(reg.assigned_bit(5).is_some());
    }

    // ---- P8 Wave B1: trust SCORE (signature ceiling, corroboration, dedup, recency, monotonicity) ----

    use super::super::Matcher;

    /// (T1) Two sources that produced the SAME set (same fingerprint) collapse into ONE list trust
    /// value = MAX over the bucket — never the sum. Re-noting the same source/fp does not double-count.
    #[test]
    fn identical_fingerprint_sources_collapse_to_one_trust_value() {
        let mut reg = SourceRegistry::new();
        let fp: u64 = 0xDEAD_BEEF_CAFE_F00D;

        // Two DISTINCT sources, same signed status, DIFFERENT reputation — both produced list `fp`.
        reg.register(SourceMeta::new(11, 50, "list A").with_reputation(40));
        reg.register(SourceMeta::new(22, 50, "list B").with_reputation(90));
        reg.note_fingerprint(11, fp);
        reg.note_fingerprint(22, fp);

        let mask = reg.mask_for(11) | reg.mask_for(22); // both arm the same domain
        let lt = list_trust(&reg, fp, mask, 0);
        let sa = trust_score(&reg, 11, mask, 0);
        let sb = trust_score(&reg, 22, mask, 0);
        assert_eq!(
            lt,
            sa.max(sb),
            "list trust is the MAX over the dedup bucket"
        );
        assert!(lt > sa, "the higher-reputation source dominates the bucket");
        assert!((lt as u16) <= sa as u16 + sb as u16, "MAX, never the SUM");

        // Re-noting the SAME source with the SAME fp is idempotent — no double-count, value unchanged.
        reg.note_fingerprint(11, fp);
        reg.note_fingerprint(22, fp);
        assert_eq!(
            reg.ids_for_fingerprint(fp).unwrap().len(),
            2,
            "bucket deduped, not grown"
        );
        assert_eq!(
            list_trust(&reg, fp, mask, 0),
            lt,
            "idempotent — same list, same trust"
        );
    }

    /// (T2) Overlap raises corroboration: as more DISTINCT sources arm the same domain, the popcount
    /// rises and the score is non-decreasing — and the corroboration bonus is CAPPED (bounded).
    #[test]
    fn overlap_raises_corroboration_and_is_capped() {
        let mut reg = SourceRegistry::new();
        // One scored source whose base is modest so corroboration has headroom to show. Unsigned so the
        // corroboration cap (not the signed band floor) is the binding upper bound under test.
        reg.register(
            SourceMeta::new(1, 30, "scored")
                .with_reputation(30)
                .with_signed(false),
        );

        let mut m = Matcher::new();
        let mut mask = 0u32;
        let mut last = 0u8;
        // Arm the same domain from 1..=4 distinct sources; popcount 1->2->3->4.
        for (i, id) in [1u32, 2, 3, 4].into_iter().enumerate() {
            let bit = reg.mask_for(id);
            mask |= bit;
            m.insert_with_source("ads.example.com", bit);
            m.finalize();
            let got = m.source_mask("ads.example.com");
            assert_eq!(SourceRegistry::corroboration(got), (i as u32) + 1);
            let s = trust_score(&reg, 1, got, 0);
            assert!(
                s >= last,
                "score must be non-decreasing as corroboration rises"
            );
            last = s;
        }

        // A 5th and 6th source must NOT push the corroboration bonus past CORR_CAP.
        let mask_56 = mask | reg.mask_for(5) | reg.mask_for(6);
        let capped = trust_score(&reg, 1, mask_56, 0);
        let base = (30u16 + 30) / 2;
        let max_with_cap = (base + CORR_CAP).min(100) as u8;
        assert!(
            capped <= max_with_cap,
            "corroboration bonus is capped at CORR_CAP"
        );
    }

    /// (T3) THE SECURITY BOUNDARY: an UNSIGNED source — even with MAX reputation/trust/overlap — is
    /// capped at `UNSIGNED_CEILING` and scores strictly BELOW a signed source with far lower inputs.
    #[test]
    fn unsigned_capped_below_any_signed() {
        let mut reg = SourceRegistry::new();
        // Signed source with modest inputs.
        reg.register(
            SourceMeta::new(1, 50, "signed")
                .with_reputation(50)
                .with_signed(true),
        );
        // Unsigned source maxed out on everything else.
        reg.register(
            SourceMeta::new(2, 100, "unsigned")
                .with_reputation(100)
                .with_signed(false),
        );

        // Give the unsigned source heavy corroboration too — it still must not breach the ceiling.
        let heavy = reg.mask_for(2) | reg.mask_for(3) | reg.mask_for(4) | reg.mask_for(5);
        let mask_signed = reg.mask_for(1);
        let signed_score = trust_score(&reg, 1, mask_signed, 0);
        let unsigned_score = trust_score(&reg, 2, heavy, 0);

        assert!(
            unsigned_score <= UNSIGNED_CEILING,
            "unsigned is capped at the ceiling"
        );
        assert!(
            signed_score >= SIGNED_FLOOR,
            "a signed source sits in the signed band"
        );
        assert!(
            unsigned_score < signed_score,
            "unsigned ({unsigned_score}) must score below signed ({signed_score}) despite higher raw inputs"
        );
    }

    /// (T4) Trust is MONOTONE under list growth: adding a new source never silently LOWERS an existing
    /// source's score. Overlap with it raises (via popcount); disjoint growth leaves it unchanged.
    #[test]
    fn trust_monotonic_under_list_growth() {
        let mut reg = SourceRegistry::new();
        reg.register(
            SourceMeta::new(1, 40, "X")
                .with_reputation(40)
                .with_signed(true),
        );

        let mut m = Matcher::new();
        let mask_x = reg.mask_for(1);
        m.insert_with_source("shared.example.com", mask_x);
        m.insert_with_source("xonly.example.com", mask_x);
        m.finalize();

        let shared_before = trust_score(&reg, 1, m.source_mask("shared.example.com"), 0);
        let xonly_before = trust_score(&reg, 1, m.source_mask("xonly.example.com"), 0);

        // A NEW source Y arms the shared domain (corroborates) AND a disjoint domain (does not touch X).
        let mask_y = reg.mask_for(2);
        m.insert_with_source("shared.example.com", mask_y); // overlap with X
        m.insert_with_source("yonly.example.com", mask_y); // disjoint from X
        m.finalize();

        let shared_after = trust_score(&reg, 1, m.source_mask("shared.example.com"), 0);
        let xonly_after = trust_score(&reg, 1, m.source_mask("xonly.example.com"), 0);

        assert!(
            shared_after >= shared_before,
            "overlap can only raise X's score (popcount up)"
        );
        assert_eq!(
            xonly_after, xonly_before,
            "disjoint growth leaves X's other domains unchanged"
        );
    }

    /// (T5) THE FINGERPRINT INVARIANT (B1 facet): attaching DIFFERENT scores/signed-flags to the SAME
    /// blocked set must NOT change `finalize()`'s fingerprint or count. The score rides ALONGSIDE the
    /// set; it is never folded into the SET hash. Mirrors `a2_provenance_never_perturbs_the_fingerprint`.
    #[test]
    fn score_never_perturbs_fingerprint() {
        let domains = ["ads.one.com", "tracker.two.io", "doubleclick.net"];

        // Same set, sources with LOW-trust UNSIGNED provenance.
        let mut reg_a = SourceRegistry::new();
        reg_a.register(
            SourceMeta::new(1, 10, "lo")
                .with_reputation(0)
                .with_signed(false),
        );
        let mut ma = Matcher::new();
        for d in domains {
            ma.insert_with_source(d, reg_a.mask_for(1));
        }
        ma.finalize();

        // SAME set, sources with HIGH-trust SIGNED provenance and recency set.
        let mut reg_b = SourceRegistry::new();
        reg_b.register(
            SourceMeta::new(1, 100, "hi")
                .with_reputation(100)
                .with_signed(true)
                .with_seen(10, 1000),
        );
        let mut mb = Matcher::new();
        for d in domains {
            mb.insert_with_source(d, reg_b.mask_for(1));
        }
        mb.finalize();

        // The scores differ wildly…
        let sa = trust_score(&reg_a, 1, ma.source_mask(domains[0]), 2000);
        let sb = trust_score(&reg_b, 1, mb.source_mask(domains[0]), 2000);
        assert_ne!(
            sa, sb,
            "provenance/score genuinely differs between the two installs"
        );
        // …but the SET fingerprint and count are byte-identical. The score never entered the hash.
        assert_eq!(
            ma.fingerprint(),
            mb.fingerprint(),
            "score must NOT perturb the SET fingerprint"
        );
        assert_eq!(ma.count(), mb.count());
    }

    /// (T6) Recency decay is bounded and neutral on unknown: an old list scores <= the same list dated
    /// today, `last_seen == 0` (unknown) yields the today value, and decay never inverts the
    /// signed/unsigned ordering.
    #[test]
    fn recency_decay_bounded_and_neutral_on_unknown() {
        let now = 2000u32;

        // Fixed-point factor sanity: fresh/unknown = 100, far past clamps to RECENCY_MIN_PCT, monotone.
        assert_eq!(recency_pct(0, now), 100, "unknown last_seen is neutral");
        assert_eq!(recency_pct(now, now), 100, "today is full weight");
        assert_eq!(
            recency_pct(now - RECENCY_FULL_DAYS, now),
            100,
            "within the full window"
        );
        assert_eq!(
            recency_pct(1, now),
            RECENCY_MIN_PCT,
            "far past clamps to the floor, never below"
        );
        // Monotone non-increasing in age.
        let mid = recency_pct(now - RECENCY_FULL_DAYS - 100, now);
        assert!(mid <= 100 && mid >= RECENCY_MIN_PCT);

        let mut reg = SourceRegistry::new();
        reg.register(
            SourceMeta::new(1, 80, "list")
                .with_reputation(80)
                .with_signed(false),
        );

        // Today vs unknown vs far-past for the SAME source.
        let mask = reg.mask_for(1);
        let mut reg_today = SourceRegistry::new();
        reg_today.register(
            SourceMeta::new(1, 80, "list")
                .with_reputation(80)
                .with_signed(false)
                .with_seen(0, now),
        );
        let mut reg_old = SourceRegistry::new();
        reg_old.register(
            SourceMeta::new(1, 80, "list")
                .with_reputation(80)
                .with_signed(false)
                .with_seen(0, 1),
        );

        let mask_today = reg_today.mask_for(1);
        let mask_old = reg_old.mask_for(1);
        let s_unknown = trust_score(&reg, 1, mask, now); // last_seen 0 ⇒ neutral
        let s_today = trust_score(&reg_today, 1, mask_today, now);
        let s_old = trust_score(&reg_old, 1, mask_old, now);

        assert_eq!(
            s_unknown, s_today,
            "unknown age scores the same as fresh-today"
        );
        assert!(
            s_old <= s_today,
            "an older list is trusted no MORE than a fresh one"
        );

        // Decay must not invert the signed/unsigned ordering: an old SIGNED source still beats a fresh
        // UNSIGNED one.
        let mut reg_cmp = SourceRegistry::new();
        reg_cmp.register(
            SourceMeta::new(1, 50, "old signed")
                .with_reputation(50)
                .with_signed(true)
                .with_seen(0, 1),
        );
        reg_cmp.register(
            SourceMeta::new(2, 100, "fresh unsigned")
                .with_reputation(100)
                .with_signed(false)
                .with_seen(0, now),
        );
        let mask_cmp_1 = reg_cmp.mask_for(1);
        let mask_cmp_2 = reg_cmp.mask_for(2);
        let old_signed = trust_score(&reg_cmp, 1, mask_cmp_1, now);
        let fresh_unsigned = trust_score(&reg_cmp, 2, mask_cmp_2, now);
        assert!(
            old_signed > fresh_unsigned,
            "recency never inverts the signature ceiling"
        );
    }
}
