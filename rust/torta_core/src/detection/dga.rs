/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **DGA recognition** — scores how algorithmically-generated one DNS label looks, entirely
//! offline. Three independent measures fuse into one 0..1 score:
//!
//! 1. **Rare-bigram fraction** against the bundled n-gram table ([`COMMON_BIGRAMS`] — a compact
//!    26×26 bitmap of the letter pairs frequent in human-named domains; the "NAND asset" ships
//!    as a const inside the `.so`, no file IO, no cloud).
//! 2. **Shannon entropy** of the label bytes (random draws run hot; words run ~3 bits/char).
//! 3. **Structure penalty** — vowel starvation + digit load + longest consonant run (human
//!    labels breathe; `xkqzwtplv` does not).
//!
//! The caller fires [`crate::underground::Signal::Dga`] at [`DGA_THRESHOLD`]. Short labels
//! (< [`MIN_LABEL_LEN`]) score 0.0 — one cannot honestly call `www` or `cdn` generated.

/// Labels shorter than this score 0.0 (too little evidence to accuse).
pub const MIN_LABEL_LEN: usize = 8;

/// Fire [`crate::underground::Signal::Dga`] at or above this score.
pub const DGA_THRESHOLD: f32 = 0.60;

/// ★ #88 — registrable domains whose CHILD LABEL IS MINTED RANDOM BY THE OPERATOR.
///
/// A CloudFront distribution is addressed as `d17vo8z6jop21h.cloudfront.net`; AWS mints that label as
/// random alphanumeric, and every other entry here does the same. High-entropy label + short TTL is
/// exactly the DGA signature, so without this the detector convicts EVERY asset served from these
/// networks — which is most of the CDN-hosted web.
///
/// MEASURED, not theorised: Socio's bench (5 track switches ~1 min apart, 2026-07-26) produced
///   `DEDUCT d17vo8z6jop21h.cloudfront.net dga -10 licence=10`
/// against the legitimate AUDIO SOURCE host for monochrome.tf playback. Two further loads would have
/// reached licence 0 and sequestrated it, killing audio while query.log still read all-PASS.
///
/// Same species as #87's operator-name defect: a signal that LOOKS like evidence but is only how an
/// operator names things. Matched on the REGISTRABLE DOMAIN (last two labels), never a substring.
pub(crate) const DISTRIBUTION_DOMAINS: &[&str] = &[
    "cloudfront.net",
    "akamaized.net",
    "akamaihd.net",
    "akamaiedge.net",
    "azureedge.net",
    "fastly.net",
    "fastlylb.net",
    "b-cdn.net",
    "kxcdn.com",
    "stackpathdns.com",
];

/// True when `host`'s random-looking leading label is an OPERATOR-MINTED DISTRIBUTION ID rather than a
/// domain someone generated to hide behind.
///
/// ★ THIS SUPPRESSES THE RANDOMNESS FEATURE ONLY. It is deliberately NOT a blanket amnesty for CDN
/// suffixes — the caller keeps every other faculty (NXDOMAIN burst, tunneling, C2 beacon) live against
/// these hosts, so genuine abuse staged behind a CDN is still scored. #87 taught the danger of vetoing
/// too broadly; this is the same lesson applied in the opposite direction.
pub(crate) fn label_is_distribution_id(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = h.split('.').filter(|l| !l.is_empty()).collect();
    // Needs a leading label PLUS the registrable domain — a bare `cloudfront.net` is not a
    // distribution ID and stays scoreable.
    if labels.len() < 3 {
        return false;
    }
    let registrable = labels[labels.len() - 2..].join(".");
    DISTRIBUTION_DOMAINS.contains(&registrable.as_str())
}

/// The bundled n-gram frequency table: bit `b` of `COMMON_BIGRAMS[a]` is set iff the letter
/// pair `(a, b)` (both 0-25) is FREQUENT in human-named/English domain labels. Built from the
/// classic English bigram frequency ranks (top ~180 pairs) plus domain-label staples
/// (`ww`, `cd`, `db`, `api`-parts). One `u32` row per first letter — 104 bytes total.
const COMMON_BIGRAMS: [u32; 26] = build_common_bigrams();

/// Compile-time constructor for [`COMMON_BIGRAMS`] — the pair list stays readable, the table
/// stays a flat bitmap.
const fn build_common_bigrams() -> [u32; 26] {
    // The frequent-pair corpus: English top bigrams + common domain-label pairs.
    const PAIRS: &[u8] = b"thheinerantirendatontenteaeststoenofedisitalarouasornthlndhaseasatetleveratsenehiricoderaralinesslimeontatilelnoloroadcecheeieldnceoemademosueceeteweerlittitutwaghcacktrupunumpluigolflcllymamanabemibleicomncoopompapepoperprressoseshsisosptatimtoubuguldunuresacadagaildowoexbebobubyjoquzajezoyoyexpvidicuffgegikekiwiwovawevo";
    let mut table = [0u32; 26];
    let mut i = 0;
    while i + 1 < PAIRS.len() {
        let a = (PAIRS[i] - b'a') as usize;
        let b = PAIRS[i + 1] - b'a';
        table[a] |= 1u32 << b;
        i += 2;
    }
    table
}

/// True iff the alpha pair `(a, b)` sits in the bundled frequent-bigram table.
fn common_bigram(a: u8, b: u8) -> bool {
    let (a, b) = (a.wrapping_sub(b'a'), b.wrapping_sub(b'a'));
    a < 26 && b < 26 && COMMON_BIGRAMS[a as usize] & (1u32 << b) != 0
}

/// Score how algorithmically-generated `label` looks, 0.0 (human) .. 1.0 (soup). Case-folded;
/// non [a-z0-9-] bytes are ignored (an IDN xn-- punycode label scores on its ASCII shape).
pub fn dga_score(label: &str) -> f32 {
    let bytes: Vec<u8> = label
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .filter(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        .collect();
    if bytes.len() < MIN_LABEL_LEN {
        return 0.0;
    }
    // 1) Rare-bigram fraction over the alpha pairs (digits/hyphens break pairs, honestly:
    //    a digit-riddled label yields few alpha pairs and is judged by measure 3 instead).
    let mut pairs = 0u32;
    let mut rare = 0u32;
    for w in bytes.windows(2) {
        if w[0].is_ascii_lowercase() && w[1].is_ascii_lowercase() {
            pairs += 1;
            if !common_bigram(w[0], w[1]) {
                rare += 1;
            }
        }
    }
    let rare_frac = if pairs == 0 { 0.5 } else { rare as f32 / pairs as f32 };
    // 2) Shannon entropy per byte, normalized against ~4.2 bits (uniform-random over the
    //    label alphabet runs ≥4.2; English words run ~2.6-3.2).
    let mut counts = [0u32; 38]; // 26 letters + 10 digits + '-' + spill
    for b in &bytes {
        let idx = match b {
            b'a'..=b'z' => (b - b'a') as usize,
            b'0'..=b'9' => 26 + (b - b'0') as usize,
            _ => 36,
        };
        counts[idx] += 1;
    }
    let n = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for c in counts {
        if c > 0 {
            let p = c as f32 / n;
            entropy -= p * p.log2();
        }
    }
    let entropy_norm = (entropy / 4.2).clamp(0.0, 1.0);
    // 3) Structure: vowel starvation, digit load, longest consonant run.
    let vowels = bytes.iter().filter(|b| matches!(b, b'a' | b'e' | b'i' | b'o' | b'u' | b'y')).count() as f32;
    let digits = bytes.iter().filter(|b| b.is_ascii_digit()).count() as f32;
    let mut run = 0u32;
    let mut worst_run = 0u32;
    for b in &bytes {
        if b.is_ascii_lowercase() && !matches!(b, b'a' | b'e' | b'i' | b'o' | b'u' | b'y') {
            run += 1;
            if run > worst_run {
                worst_run = run;
            }
        } else {
            run = 0;
        }
    }
    let mut structure = 0.0f32;
    if vowels / n < 0.20 {
        structure += 0.5;
    }
    if digits / n > 0.30 {
        structure += 0.3;
    }
    if worst_run >= 5 {
        structure += 0.4;
    }
    let structure = structure.clamp(0.0, 1.0);
    (0.45 * rare_frac + 0.30 * entropy_norm + 0.25 * structure).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {

    /// A5 GUARD -- `MIN_LABEL_LEN` (= 8, detection/dga.rs:21) is the evidence floor under the DGA
    /// scorer: a label shorter than this scores 0.0 because "one cannot honestly call `www` or
    /// `cdn` generated". The A5 inventory found it had a NUMBER and no test naming it.
    ///
    /// This bound protects the USER, not the device. Lowering it does not weaken a defence -- it
    /// manufactures ACCUSATIONS against short, ordinary labels, and the visible result is a
    /// dashboard calling `cdn` malware. Both directions, so the floor is a bound and not a
    /// constant.
    #[test]
    fn min_label_len_is_the_evidence_floor_for_a_dga_accusation() {
        for short in ["www", "cdn", "api", "x7q", "zxqvbn"] {
            assert!(short.len() < MIN_LABEL_LEN);
            assert_eq!(
                dga_score(short),
                0.0,
                "{short:?} is under MIN_LABEL_LEN -- too little evidence to accuse"
            );
        }
        // Non-vacuity: at the floor the scorer is still ALIVE. Without this arm a blanket
        // `return 0.0` would satisfy every assertion above.
        let long_random = "xqzkvbwj";
        assert_eq!(long_random.len(), MIN_LABEL_LEN);
        assert!(
            dga_score(long_random) > 0.0,
            "a label AT the floor must be scorable, or the floor has disabled the detector"
        );
        assert!(
            dga_score("newsletter") < DGA_THRESHOLD,
            "an ordinary English-shaped label must not be accused"
        );
    }

    use super::*;

    #[test]
    fn a_distribution_id_is_exempt_but_only_under_a_real_distribution_domain() {
        // ★ #88 — the MEASURED host. Its leading label scores as pure DGA shape on its own...
        assert!(dga_score("d17vo8z6jop21h") >= DGA_THRESHOLD, "premise: the label does read as DGA");
        // ...and that is exactly why the structural exemption is needed.
        assert!(label_is_distribution_id("d17vo8z6jop21h.cloudfront.net"));
        assert!(label_is_distribution_id("a1b2c3d4e5f6g7.akamaized.net"));
        assert!(label_is_distribution_id("xkqzwtplv.azureedge.net"));

        // THE OTHER DIRECTION — the exemption must stay narrow or it becomes a hiding place.
        // A random label under an ORDINARY domain is still scored.
        assert!(!label_is_distribution_id("xkqzwtplvmnrbds.example.com"));
        // The bare registrable domain is NOT a distribution ID (no child label to mint).
        assert!(!label_is_distribution_id("cloudfront.net"));
        // A lookalike that merely CONTAINS the name must not slip through — match is on the
        // registrable domain, never a substring.
        assert!(!label_is_distribution_id("xkqzwtplv.notcloudfront.net"));
        assert!(!label_is_distribution_id("xkqzwtplv.cloudfront.net.evil.tld"));
    }

    #[test]
    fn alphabet_soup_fires_and_words_do_not() {
        // Synthetic DGA shapes (the recipe's xkqzwt[...] family) run hot.
        assert!(dga_score("xkqzwtplvmnrbds") >= DGA_THRESHOLD);
        assert!(dga_score("qwjzxkvbpfmtghd") >= DGA_THRESHOLD);
        // Real hostnames breathe — all far under the line.
        for legit in ["wikipedia", "microsoft", "cloudfront", "telemetry", "appmeasurement"] {
            assert!(dga_score(legit) < DGA_THRESHOLD, "{legit} misfired: {}", dga_score(legit));
        }
    }

    #[test]
    fn short_labels_are_never_accused() {
        for s in ["www", "cdn", "api", "a1-b2", "ns"] {
            assert_eq!(dga_score(s), 0.0);
        }
    }

    #[test]
    fn fp_control_legit_cdn_hosts_stay_quiet() {
        // The recipe's FP gate: high-QPS CDN label shapes must NOT fire.
        for cdn in ["googleapis", "akamaiedge", "ecloudfront", "gstaticadssl", "amazonaws"] {
            assert!(dga_score(cdn) < DGA_THRESHOLD, "{cdn} misfired: {}", dga_score(cdn));
        }
    }
}
