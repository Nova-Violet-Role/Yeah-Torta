/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! P10 rotation + warm-RTT **durable state** — the resolver's NEW-durable W5 pillar.
//!
//! The resolver's hot in-memory state (the pool, the cache) is rebuilt on every `configure` and is
//! deliberately VOLATILE. But two small bits are worth carrying across a power-off/reboot so the next
//! boot starts WARM instead of cold (W5 CHARTER §"The pillars to wire" — Resolver + Rotation rows):
//!   - **rotation cursor** — the last operator family selected + the rotation cadence + the last
//!     rotation index, so a P10 rotation resumes its schedule across a reboot instead of restarting at
//!     family 0 (ties #98 auto-start — a rebooted phone keeps its rotation cadence).
//!   - **warm RTT hints** — a tiny `(upstream_id → last_rtt_ms)` map so the next boot's pool can prefer
//!     the upstream that was fastest last session, instead of re-learning RTT from a flat cold pool.
//!
//! ## Where it sits (the no-hot-path-write law — the keystone safety invariant)
//! This state is **NOT** on the `resolve()` hot path. It is read ONCE at start
//! ([`RotationState::rehydrate`]) and written ONLY on the control plane — a rotation flip / a periodic
//! checkpoint ([`RotationState::persist`]) — exactly the GENTLE write-through the charter mandates.
//! `resolver/mod.rs`'s `resolve_inner` is untouched + byte-identical: it never constructs, reads, or
//! writes this. The durable seam is the shared [`crate::runtime_tier::DurableTier`] (atomic tmp+rename,
//! integrity-checked, non-failing rehydrate, bounded), so a corrupt/half-written record degrades to a
//! cold start (the in-memory resolver keeps working — durable is best-effort).
//!
//! ## Serialization (tiny, hand-rolled, no serde — the 2b discipline)
//! The durable payload is a tiny, line-oriented text record (the SAME no-serde posture as
//! `resolver/mod.rs`'s hand-rolled upstream parser — smaller `.so`, one less dep). A malformed field is
//! skipped (the record reader is bounds-checked + tolerant), and the [`DurableTier`] integrity frame
//! already guarantees the bytes are intact before this reader ever sees them.
//!
//! `#![forbid(unsafe_code)]`, std-only, zero new deps. WIRED (P10, #98): the crate-root JNI exports
//! (`rehydrate_resolver_rotation` · `persist_resolver_rotation` · `checkpoint_resolver_rotation` ·
//! `warm_start_resolver_rtt`, `lib.rs`) + the Kotlin `RotationManager` boot-rehydrate / rotate-commit /
//! periodic-checkpoint seams drive it — the cursor now resumes WARM across a reboot, the warm-RTT hints
//! are refreshed on the control-plane checkpoint, and the boot pool warm-start consumes them. Still
//! `resolve_inner`-free: every seam is control-plane / boot, never the resolve path.

#![forbid(unsafe_code)]

use std::path::PathBuf;

use crate::runtime_tier::DurableTier;

/// The stable on-disk record name for the resolver's durable rotation/RTT state (under the app-private
/// dir). One record per pillar; the [`DurableTier`] sanitizes it to a traversal-free filename.
const RECORD_NAME: &str = "resolver-rotation";

/// A bound on the number of warm RTT hints carried across a reboot. The pool is small (a handful of
/// upstreams), so 64 is a generous fail-closed ceiling — a hostile/corrupt record claiming thousands of
/// hints is truncated here (bounded footprint), and the [`DurableTier`]'s `MAX_BLOB_BYTES` is the outer
/// guard. NOT a tuning knob.
pub const MAX_RTT_HINTS: usize = 64;

/// The resolver's durable rotation cursor + warm RTT hints — the NEW-durable bits, in memory.
///
/// This is the OWNING in-RAM state (the W5 "RAM tier" = the app heap); the [`DurableTier`] is only its
/// durable seam. Built cold by default ([`RotationState::cold`]); [`RotationState::rehydrate`] warms it
/// from disk at start; [`RotationState::persist`] gently writes it back on a control-plane event.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RotationState {
    /// The operator family selected at the last rotation (e.g. `"cloudflare"`, `"quad9"`), or empty if
    /// none has rotated yet. Opaque to this module — the P10 scheduler defines the family vocabulary.
    pub last_family: String,
    /// The rotation cadence in seconds (0 ⇒ unset / rotation disabled). Persisted so a reboot resumes
    /// the user's chosen cadence rather than a default.
    pub cadence_secs: u64,
    /// The last rotation index (a monotonically advancing cursor the scheduler steps each rotation).
    /// Persisted so rotation resumes WHERE it left off across a reboot, not at 0.
    pub rotation_index: u64,
    /// Warm RTT hints — `(upstream_id, last_rtt_ms)`, bounded to [`MAX_RTT_HINTS`]. The next boot's pool
    /// may prefer the fastest last-known upstream. A `Vec` (not a map) — the set is tiny + this avoids a
    /// hashmap dep on a payload this small; lookups are linear over ≤64 entries.
    pub rtt_hints: Vec<(String, u32)>,
}

impl RotationState {
    /// A fresh cold rotation state (no family, no cadence, index 0, no hints) — the zero baseline a
    /// boot starts from when there is no durable record (a cold start).
    pub fn cold() -> Self {
        RotationState::default()
    }

    /// Record an upstream's measured RTT (ms) as a warm hint for the NEXT boot. Updates an existing hint
    /// for the same id in place; appends a new one only while under [`MAX_RTT_HINTS`] (bounded footprint
    /// — a full hint set silently drops a brand-new upstream's hint rather than growing unbounded). This
    /// is a CONTROL-PLANE bookkeeping call (the pool's stats checkpoint), NEVER the per-query hot path.
    pub fn observe_rtt(&mut self, upstream_id: &str, rtt_ms: u32) {
        if let Some(slot) = self.rtt_hints.iter_mut().find(|(id, _)| id == upstream_id) {
            slot.1 = rtt_ms;
            return;
        }
        if self.rtt_hints.len() < MAX_RTT_HINTS {
            self.rtt_hints.push((upstream_id.to_string(), rtt_ms));
        }
    }

    /// The warm RTT hint for an upstream id, if any — the next-boot pool's "prefer the fastest last time"
    /// read. WIRED (#98): the boot pool warm-start (`resolver::warm_start_pool_rtt` →
    /// `Pool::warm_start_rtt`) consumes this to seed each UNLEARNED transport's RTT EWMA from its
    /// last-known value, so `Strategy::Fastest` starts warm instead of cold (`f64::INFINITY`) — a
    /// control-plane call at boot, NEVER the resolve path. No longer dead-code (the pool consumer landed).
    pub fn rtt_hint(&self, upstream_id: &str) -> Option<u32> {
        self.rtt_hints
            .iter()
            .find(|(id, _)| id == upstream_id)
            .map(|(_, rtt)| *rtt)
    }

    /// Advance the rotation cursor to a new family + index (a P10 rotation flip), keeping the cadence.
    /// A control-plane call; persist afterwards to make it durable across a reboot.
    pub fn rotate_to(&mut self, family: &str, index: u64) {
        self.last_family = family.to_string();
        self.rotation_index = index;
    }

    // ---- the durable seam (GENTLE write-through + explicit rehydrate, via DurableTier) ----------------

    /// The [`DurableTier`] for this pillar rooted at the app-private `dir`. Constructing it does NO disk
    /// IO (the no-boot-IO-scan law) — the caller rehydrates/persists explicitly.
    pub fn tier(dir: PathBuf) -> DurableTier {
        DurableTier::with_dir(dir, RECORD_NAME)
    }

    /// Rehydrate the rotation state from the app-private `dir`, returning a warm [`RotationState`] (or a
    /// cold one if there is no valid record). EXPLICIT + non-failing: a missing / corrupt / oversized /
    /// tampered record yields [`RotationState::cold`] (a cold start), never an error — the [`DurableTier`]
    /// integrity frame is the fail-safe gate, and a malformed field inside an intact record is skipped.
    /// Call this ONCE at start (boot / DNSCrypt-start), NEVER on the resolve path.
    pub fn rehydrate(dir: PathBuf) -> RotationState {
        Self::rehydrate_opt(dir).unwrap_or_else(RotationState::cold)
    }

    /// The FOUND-signalling sibling of [`rehydrate`](RotationState::rehydrate): `Some(state)` when a durable
    /// record was present AND read back (a WARM resume), `None` when there is NO record on disk or the bytes
    /// fail the [`DurableTier`] integrity / UTF-8 gate (a COLD start). Both variants share the SAME fail-safe
    /// read — this one only tells the caller WHICH happened. The dashboard's "resumed warm" flag
    /// ([`crate::resolver::object::RotationSnapshot::rehydrated_warm`]) needs to distinguish "no record" from
    /// "a record that decoded to cold-ish values" — a distinction `== cold()` cannot make. A (rare)
    /// intact-but-all-default record still counts as FOUND (a real record WAS persisted). NEVER on the
    /// resolve path — a control-plane / boot read.
    pub fn rehydrate_opt(dir: PathBuf) -> Option<RotationState> {
        match Self::tier(dir).rehydrate() {
            Some(bytes) => Self::decode(&bytes),
            None => None,
        }
    }

    /// GENTLY persist this rotation state to the app-private `dir`, atomically (via [`DurableTier`]).
    /// Returns `true` on a durable write, `false` on any refusal (best-effort — the in-memory state is
    /// unaffected; the charter's FAIL-SAFE invariant). **Call this ONLY on the control plane** (a
    /// rotation flip / a periodic checkpoint), NEVER from `resolve()`.
    pub fn persist(&self, dir: PathBuf) -> bool {
        Self::tier(dir).write_through(&self.encode()).is_ok()
    }

    /// Encode the rotation state into the tiny line-oriented durable payload (no serde — the 2b
    /// discipline). Format (one `key=value` per line; values are escaped of `\n`/`=` for the RTT id):
    /// `family=<s>` · `cadence=<u64>` · `index=<u64>` · `rtt=<id>:<ms>` (one per hint).
    fn encode(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str("family=");
        s.push_str(&escape(&self.last_family));
        s.push('\n');
        s.push_str(&format!("cadence={}\n", self.cadence_secs));
        s.push_str(&format!("index={}\n", self.rotation_index));
        for (id, rtt) in self.rtt_hints.iter().take(MAX_RTT_HINTS) {
            s.push_str("rtt=");
            s.push_str(&escape(id));
            s.push(':');
            s.push_str(&rtt.to_string());
            s.push('\n');
        }
        s.into_bytes()
    }

    /// Decode the durable payload back into a [`RotationState`]. Tolerant + bounds-checked: an unknown
    /// key or a malformed value is SKIPPED (never a hard failure — the record bytes are already
    /// integrity-verified by [`DurableTier`], so this only guards against a value that does not parse).
    /// Returns `Some(state)` for any (even partially) readable record; the caller maps a `None` framing
    /// failure to a cold start upstream. RTT hints past [`MAX_RTT_HINTS`] are dropped (bounded).
    fn decode(bytes: &[u8]) -> Option<RotationState> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut state = RotationState::cold();
        for line in text.lines() {
            let (key, value) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue, // a line without '=' is malformed → skip.
            };
            match key {
                "family" => state.last_family = unescape(value),
                "cadence" => {
                    if let Ok(v) = value.parse::<u64>() {
                        state.cadence_secs = v;
                    }
                }
                "index" => {
                    if let Ok(v) = value.parse::<u64>() {
                        state.rotation_index = v;
                    }
                }
                "rtt" => {
                    if state.rtt_hints.len() >= MAX_RTT_HINTS {
                        continue; // bounded — drop hints past the ceiling.
                    }
                    // `<id>:<ms>` — split on the LAST ':' so an escaped id never confuses the rtt parse.
                    if let Some((id_esc, ms)) = value.rsplit_once(':') {
                        if let Ok(rtt) = ms.parse::<u32>() {
                            state.rtt_hints.push((unescape(id_esc), rtt));
                        }
                    }
                }
                _ => continue, // unknown key → forward-tolerant skip.
            }
        }
        Some(state)
    }
}

/// Escape `\` `\n` `=` `:` in a field value so a family name / upstream id can never break the
/// line-oriented framing. Reversed by [`unescape`]. Bounded, never panics.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '=' => out.push_str("\\e"),
            ':' => out.push_str("\\c"),
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`escape`]. An unterminated/unknown escape is passed through literally (tolerant).
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('e') => out.push('='),
            Some('c') => out.push(':'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("torta-w5-rot-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn cold_is_the_zero_baseline() {
        let s = RotationState::cold();
        assert!(s.last_family.is_empty());
        assert_eq!(s.cadence_secs, 0);
        assert_eq!(s.rotation_index, 0);
        assert!(s.rtt_hints.is_empty());
    }

    #[test]
    fn rehydrate_on_cold_dir_is_cold_not_error() {
        let dir = temp_dir("cold");
        let s = RotationState::rehydrate(dir.clone());
        assert_eq!(
            s,
            RotationState::cold(),
            "no record ⇒ a cold start, never an error"
        );
        assert!(
            !dir.exists(),
            "rehydrate of an absent record touches no disk"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persist_then_rehydrate_round_trips_the_cursor_and_hints() {
        let dir = temp_dir("roundtrip");
        let mut s = RotationState::cold();
        s.cadence_secs = 3600;
        s.rotate_to("cloudflare", 7);
        s.observe_rtt("doh:cf", 21);
        s.observe_rtt("dnscrypt:quad9", 35);
        assert!(
            s.persist(dir.clone()),
            "a control-plane persist writes durably"
        );

        // A fresh "boot" rehydrates the EXACT warm state.
        let warm = RotationState::rehydrate(dir.clone());
        assert_eq!(
            warm, s,
            "rotation cursor + cadence + RTT hints survive a reboot"
        );
        assert_eq!(warm.rtt_hint("doh:cf"), Some(21));
        assert_eq!(warm.rtt_hint("dnscrypt:quad9"), Some(35));
        assert_eq!(warm.rtt_hint("absent"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observe_rtt_updates_in_place_and_is_bounded() {
        let mut s = RotationState::cold();
        s.observe_rtt("a", 10);
        s.observe_rtt("a", 99); // same id ⇒ in-place update, no duplicate.
        assert_eq!(s.rtt_hints.len(), 1);
        assert_eq!(s.rtt_hint("a"), Some(99));
        // Fill to the ceiling, then a new id is dropped (bounded footprint).
        for i in 0..MAX_RTT_HINTS as u32 {
            s.observe_rtt(&format!("u{i}"), i);
        }
        assert!(
            s.rtt_hints.len() <= MAX_RTT_HINTS,
            "the hint set never exceeds its bound"
        );
        let over = "over-the-cap";
        s.observe_rtt(over, 1);
        assert_eq!(
            s.rtt_hint(over),
            None,
            "a brand-new hint past the cap is dropped, not grown"
        );
    }

    #[test]
    fn escape_unescape_round_trips_nasty_ids() {
        // A family/id carrying the framing delimiters must round-trip losslessly.
        for raw in [
            "plain",
            "with=eq",
            "with:colon",
            "with\nnewline",
            "back\\slash",
            "all=:\n\\of",
        ] {
            assert_eq!(unescape(&escape(raw)), raw, "escape round-trips {raw:?}");
        }
    }

    #[test]
    fn nasty_id_round_trips_through_persist() {
        let dir = temp_dir("nasty");
        let mut s = RotationState::cold();
        s.rotate_to("family=with:weird\nchars\\here", 3);
        s.observe_rtt("id=with:delims\n", 42);
        assert!(s.persist(dir.clone()));
        let warm = RotationState::rehydrate(dir.clone());
        assert_eq!(warm.last_family, "family=with:weird\nchars\\here");
        assert_eq!(warm.rtt_hint("id=with:delims\n"), Some(42));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_record_rehydrates_cold_fail_safe() {
        let dir = temp_dir("corrupt");
        let s = {
            let mut s = RotationState::cold();
            s.rotate_to("quad9", 2);
            s
        };
        assert!(s.persist(dir.clone()));
        // Tamper the on-disk payload — the DurableTier integrity frame fails ⇒ rehydrate is cold.
        let path = RotationState::tier(dir.clone()).path();
        let mut raw = std::fs::read(&path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();
        assert_eq!(
            RotationState::rehydrate(dir.clone()),
            RotationState::cold(),
            "a corrupt durable record degrades to a cold start (fail-safe)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decode_drops_hints_past_the_ceiling_however_large_the_record() {
        // The hint ceiling is tested above for `observe_rtt`, the path THIS process controls. It was
        // NOT tested for `decode`, the path it does not: `rtt_hints` is rehydrated from
        // app_data/runtime_tier/resolver-rotation, a file on the device, and `decode` is deliberately
        // forward-tolerant. The number of `rtt=` lines is therefore attacker- or corruption-influenced,
        // and the `continue` at the ceiling is the only thing between that file and unbounded resident
        // memory. 5000 lines is a stand-in for "any size at all".
        let mut payload = String::from("family=cf\ncadence=1800\nindex=3\n");
        for i in 0..5000u32 {
            payload.push_str(&format!("rtt=u{i}:{}\n", i % 400));
        }
        let s = RotationState::decode(payload.as_bytes()).expect("a readable record decodes");
        assert_eq!(
            s.rtt_hints.len(),
            MAX_RTT_HINTS,
            "a 5000-hint record rehydrates to exactly the ceiling, never more"
        );
        // The non-hint fields still load — the ceiling drops the excess, it does not abort the record.
        assert_eq!(s.last_family, "cf");
        assert_eq!(s.cadence_secs, 1800);
        assert_eq!(s.rotation_index, 3);
        // And the retained ones are the FIRST seen, which is the documented drop policy (rotation.rs:87
        // -- a full set drops the newcomer). Pinned so a change of policy has to be deliberate.
        assert_eq!(s.rtt_hints[0].0, "u0");
        assert_eq!(
            s.rtt_hints[MAX_RTT_HINTS - 1].0,
            format!("u{}", MAX_RTT_HINTS - 1)
        );

        // An encode of that state re-emits at most the ceiling, so the file cannot grow across a
        // save/load cycle either -- the composition the app performs on every restart.
        let reborn = RotationState::decode(&s.encode()).expect("the re-encoded record decodes");
        assert_eq!(reborn.rtt_hints.len(), MAX_RTT_HINTS);
    }

    #[test]
    fn decode_skips_malformed_fields_tolerantly() {
        // An intact record (integrity-OK) with a bad numeric value + an unknown key: the good fields
        // load, the bad ones are skipped — never a hard failure.
        let payload =
            b"family=cf\ncadence=not-a-number\nindex=5\nunknown=whatever\nrtt=x:bad\nrtt=y:12\n";
        let s = RotationState::decode(payload).expect("a readable record decodes");
        assert_eq!(s.last_family, "cf");
        assert_eq!(
            s.cadence_secs, 0,
            "a malformed cadence is skipped (stays default)"
        );
        assert_eq!(s.rotation_index, 5, "the good index loads");
        assert_eq!(s.rtt_hint("x"), None, "a malformed rtt value is skipped");
        assert_eq!(s.rtt_hint("y"), Some(12), "the good rtt hint loads");
    }

    #[test]
    fn reboot_resumes_warm_not_cold_at_family_zero() {
        // The #98 point: a rebooted phone must resume its rotation SCHEDULE, not restart cold at family 0.
        let dir = temp_dir("reboot-warm");
        let mut s = RotationState::cold();
        s.cadence_secs = 1800;
        s.rotate_to("mullvad", 5); // mid-schedule: family "mullvad", index 5.
        assert!(s.persist(dir.clone()));

        // A fresh process ("reboot") rehydrates — NOT the cold family-0 baseline.
        let warm = RotationState::rehydrate(dir.clone());
        assert_ne!(
            warm,
            RotationState::cold(),
            "a reboot resumes warm, never cold"
        );
        assert_eq!(
            warm.last_family, "mullvad",
            "the last operator family survives the reboot (no re-land at family 0)"
        );
        assert_eq!(warm.rotation_index, 5, "rotation resumes at index 5, NOT 0");
        assert_eq!(
            warm.cadence_secs, 1800,
            "the chosen cadence survives the reboot"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flip_rehydrate_then_recursor_preserves_accumulated_rtt_hints() {
        // The flip-persist rehydrates FIRST so a rotation flip does not WIPE the warm-RTT hints the
        // periodic checkpoint accumulated (the `lib.rs::persist_resolver_rotation` contract, modeled here
        // at the state level): a checkpoint persists hints under an old cursor; a flip rehydrates,
        // re-cursors, and persists — the hints survive under the NEW cursor.
        let dir = temp_dir("flip-preserves-rtt");
        // Checkpoint: cursor (quad9, idx 3) + two warm hints.
        let mut checkpoint = RotationState::cold();
        checkpoint.cadence_secs = 900;
        checkpoint.rotate_to("quad9", 3);
        checkpoint.observe_rtt("doh:cf", 18);
        checkpoint.observe_rtt("dnscrypt:quad9", 27);
        assert!(checkpoint.persist(dir.clone()));

        // Flip: rehydrate (PRESERVE the hints) → set the NEW cursor → persist.
        let mut flip = RotationState::rehydrate(dir.clone());
        flip.rotate_to("cloudflare", 4);
        assert!(flip.persist(dir.clone()));

        // A reboot sees the NEW cursor AND the preserved warm hints.
        let warm = RotationState::rehydrate(dir.clone());
        assert_eq!(
            warm.last_family, "cloudflare",
            "the flip's new family landed"
        );
        assert_eq!(warm.rotation_index, 4, "the flip's new index landed");
        assert_eq!(
            warm.rtt_hint("doh:cf"),
            Some(18),
            "the checkpoint's RTT hint survived the flip (rehydrate-first, not wiped)"
        );
        assert_eq!(
            warm.rtt_hint("dnscrypt:quad9"),
            Some(27),
            "…both accumulated hints survived the flip"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rehydrate_opt_signals_found_vs_absent() {
        // rehydrate_opt is the FOUND-vs-cold signal the dashboard's `rehydrated_warm` flag needs: `None` when
        // there is no record, `Some(state)` when a durable record was persisted + read back — while plain
        // `rehydrate` maps BOTH to `cold()` (indistinguishable via `==`).
        let dir = temp_dir("opt");
        assert!(
            RotationState::rehydrate_opt(dir.clone()).is_none(),
            "no record ⇒ None (a cold start)"
        );
        assert_eq!(
            RotationState::rehydrate(dir.clone()),
            RotationState::cold(),
            "…and plain rehydrate on that same absent record is cold"
        );

        let mut s = RotationState::cold();
        s.cadence_secs = 900;
        s.rotate_to("cloudflare", 3);
        s.observe_rtt("doh:cf", 19);
        assert!(s.persist(dir.clone()));

        let found = RotationState::rehydrate_opt(dir.clone())
            .expect("a persisted record ⇒ Some (a warm resume)");
        assert_eq!(found, s, "the found record round-trips exactly");
        assert_eq!(
            RotationState::rehydrate(dir.clone()),
            found,
            "rehydrate == rehydrate_opt().unwrap_or(cold) — the shared fail-safe read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
