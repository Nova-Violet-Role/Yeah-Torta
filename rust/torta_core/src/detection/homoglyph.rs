/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! **Punycode/homoglyph brand-forgery recognition** (61F) — the IDN-homograph and
//! digit-swap phish shape the suffix matcher never can see: a label that *renders* as a
//! high-value brand but *is not* that brand (`xn--pple-43d` → Cyrillic "аpple";
//! `paypa1`/`g00gle`). Pure faculty: an `xn--` label runs through a minimal RFC 3492
//! decoder (decode-only, overflow-guarded, fail-open), then every char folds through a
//! bundled confusable table to an ASCII skeleton; a skeleton that EQUALS a
//! [`BRAND_SKELETONS`] entry while the raw label does NOT is the forgery tell. The brand
//! itself can never fire on itself (the raw-label exclusion below). Fully offline — both
//! tables ship inside the `.so` (the [`super::dga`] `COMMON_BIGRAMS` precedent); no state,
//! no clock, no lock.

/// High-value forgery targets — small and curated (the bundled-table law). Skeletons are
/// pure lowercase ASCII; a folded label must match EXACTLY (no substring scoring — a
/// `googlemaps` bystander never fires).
pub const BRAND_SKELETONS: &[&str] = &[
    "amazon",
    "apple",
    "binance",
    "coinbase",
    "discord",
    "dnscrypt",
    "facebook",
    "github",
    "gmail",
    "google",
    "instagram",
    "microsoft",
    "netflix",
    "paypal",
    "signal",
    "steam",
    "telegram",
    "torproject",
    "whatsapp",
    "youtube",
];

/// RFC 3492 §6.2 decode (decode-only). `None` on ANY irregularity — the fail-open law: an
/// undecodable label stays opaque and unscored, never panicked over. Overflow rides
/// checked arithmetic, not process death.
pub(crate) fn punycode_decode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    fn adapt(delta: u32, numpoints: u32, first: bool) -> u32 {
        let mut delta = if first { delta / DAMP } else { delta / 2 };
        delta += delta / numpoints;
        let mut k = 0;
        while delta > ((BASE - TMIN) * TMAX) / 2 {
            delta /= BASE - TMIN;
            k += BASE;
        }
        k + (((BASE - TMIN + 1) * delta) / (delta + SKEW))
    }
    let (mut output, extended) = match input.rfind('-') {
        Some(pos) => (
            input[..pos].chars().collect::<Vec<char>>(),
            &input[pos + 1..],
        ),
        None => (Vec::new(), input),
    };
    if output.iter().any(|c| !c.is_ascii()) || extended.is_empty() {
        return None;
    }
    let digits: Vec<u32> = extended
        .chars()
        .map(|c| match c {
            'a'..='z' => Some(c as u32 - 'a' as u32),
            'A'..='Z' => Some(c as u32 - 'A' as u32),
            '0'..='9' => Some(c as u32 - '0' as u32 + 26),
            _ => None,
        })
        .collect::<Option<Vec<u32>>>()?;
    let mut n: u32 = 128;
    let mut i: u32 = 0;
    let mut bias: u32 = 72;
    let mut pos = 0;
    while pos < digits.len() {
        let oldi = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let digit = *digits.get(pos)?;
            pos += 1;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let len1 = output.len() as u32 + 1;
        bias = adapt(i - oldi, len1, oldi == 0);
        n = n.checked_add(i / len1)?;
        i %= len1;
        output.insert(i as usize, char::from_u32(n)?);
        i += 1;
    }
    Some(output.into_iter().collect())
}

/// Fold one rendered label to its ASCII confusable skeleton: lowercase, then the bundled
/// per-char table (digit swaps + Cyrillic + Greek + Latin-extended lookalikes), then the
/// two classic digraphs (`rn`→`m`, `vv`→`w`). Unmapped chars pass through untouched — a
/// genuinely foreign word never collides with an ASCII brand skeleton.
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.to_lowercase().chars() {
        out.push(match c {
            // Digit-for-letter swaps (the `paypa1` lane).
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            '8' => 'b',
            '9' => 'g',
            // Cyrillic lookalikes (the IDN-homograph lane).
            'а' => 'a',
            'е' => 'e',
            'о' => 'o',
            'р' => 'p',
            'с' => 'c',
            'у' => 'y',
            'х' => 'x',
            'і' => 'i',
            'ј' => 'j',
            'ѕ' => 's',
            'ԁ' => 'd',
            'к' => 'k',
            'м' => 'm',
            'т' => 't',
            'в' => 'b',
            'ѡ' => 'w',
            'ԛ' => 'q',
            'ԝ' => 'w',
            'ӏ' => 'l', // palochka — the famous all-Cyrillic "аррӏе"
            // Greek lookalikes.
            'ο' => 'o',
            'α' => 'a',
            'ν' => 'v',
            'ι' => 'i',
            'κ' => 'k',
            'ρ' => 'p',
            'τ' => 't',
            'υ' => 'u',
            'χ' => 'x',
            'ε' => 'e',
            'η' => 'n',
            'ω' => 'w',
            'ϲ' => 'c',
            'ϳ' => 'j',
            // Latin-extended strays.
            'ı' => 'i',
            'ł' => 'l',
            'ɡ' => 'g',
            other => other,
        });
    }
    out.replace("rn", "m").replace("vv", "w")
}

/// Judge ONE label: `Some(brand)` when its rendered form folds EXACTLY onto a
/// [`BRAND_SKELETONS`] entry while the raw label is not that brand (the self-exclusion —
/// `google` can never convict `google`). `xn--` labels decode first (RFC 3492,
/// fail-open); everything else folds as-is. Pure — no state, no clock.
pub fn homoglyph_hit(label: &str) -> Option<&'static str> {
    let raw = label.to_lowercase();
    let rendered = match raw.strip_prefix("xn--") {
        Some(rest) => punycode_decode(rest)?,
        None => raw.clone(),
    };
    let folded = fold(&rendered);
    BRAND_SKELETONS
        .iter()
        .copied()
        .find(|b| folded == *b && raw != *b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_brand_labels_never_fire_on_themselves() {
        for b in BRAND_SKELETONS {
            assert_eq!(homoglyph_hit(b), None, "{b} convicted itself");
        }
    }

    #[test]
    fn ascii_confusable_forgeries_fire() {
        assert_eq!(homoglyph_hit("g00gle"), Some("google"));
        assert_eq!(homoglyph_hit("paypa1"), Some("paypal"));
        assert_eq!(homoglyph_hit("arnazon"), Some("amazon")); // rn → m digraph
        assert_eq!(homoglyph_hit("rnicrosoft"), Some("microsoft"));
        assert_eq!(homoglyph_hit("faceb00k"), Some("facebook"));
    }

    #[test]
    fn punycode_homograph_fires() {
        // xn--pple-43d renders as Cyrillic-а "аpple" — the canonical IDN homograph.
        assert_eq!(homoglyph_hit("xn--pple-43d"), Some("apple"));
    }

    #[test]
    fn rfc3492_canonical_decode_round_trip() {
        // The RFC's own example: "bcher-kva" → "bücher".
        assert_eq!(punycode_decode("bcher-kva").as_deref(), Some("bücher"));
    }

    #[test]
    fn undecodable_and_bystander_labels_stay_quiet() {
        assert_eq!(homoglyph_hit("xn--!!!"), None); // fail-open, not a panic
        assert_eq!(homoglyph_hit("xn--"), None);
        assert_eq!(homoglyph_hit(""), None);
        assert_eq!(homoglyph_hit("www"), None);
        assert_eq!(homoglyph_hit("googlemaps"), None); // no substring scoring
    }
}
