/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! engine — the 60C TEXT-MODE lane (v0): a REAL, running browser page pass in
//! the carbonyl look. NOT the Chromium assimilation (that stays the 60C
//! roadmap — carbonyl-main is a Chromium fork and does not cross-compile in
//! one wave); this is a Rust-native HTML → text-cell document pass, so the
//! Carbon pane genuinely BROWSES today: fetch rides the host lane (Kotlin
//! `HttpsURLConnection`, platform TLS 1.3 — traffic inside the YeAH Tortä
//! tunnel like every other socket = sandboxed), and THIS module turns the
//! bytes into an honest terminal page.
//!
//! FELT-TRUTH LAW: every line emitted comes from the fetched document — no
//! sample pages, no canned lorem. A fetch failure renders AS a failure.
//!
//! Integration code: AGPL/EUPL dual, (c) Saimonokuma (the #38-41 REUSE lane).

/// A parsed text-mode page — what the Slint terminal pane renders.
pub struct PageDoc {
    /// `<title>` content, entity-decoded ("" when the document has none)
    pub title: String,
    /// the visible text, one logical block per line, links annotated `[n]`
    pub lines: Vec<String>,
    /// the numbered link targets (`[1]` → links[0])
    pub links: Vec<String>,
}

/// Hard caps — a terminal page, not a heap flood.
const MAX_LINES: usize = 800;
const MAX_LINE_CHARS: usize = 400;
const MAX_LINKS: usize = 200;

/// Decode the entity references that actually matter for text-mode reading.
fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
}

/// True when `tag` ends the current text block (a terminal line break).
fn is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "div" | "br" | "li" | "ul" | "ol" | "tr" | "table" | "h1" | "h2" | "h3" | "h4"
            | "h5" | "h6" | "section" | "article" | "header" | "footer" | "nav" | "main"
            | "blockquote" | "pre" | "hr" | "form" | "aside" | "figure" | "figcaption" | "dd"
            | "dt" | "dl" | "address" | "summary" | "details"
    )
}

/// The 60C text-mode document pass: strip `<script>`/`<style>`, honor block
/// tags as line breaks, number `<a href>` targets, decode entities, cap
/// everything. Pure function — trivially testable, no I/O.
pub fn parse_document(html: &str, url: &str) -> PageDoc {
    let mut title = String::new();
    let mut lines: Vec<String> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    let mut cur = String::new();

    let bytes = html.as_bytes();
    let mut i = 0usize;
    let mut in_title = false;
    // the tag-skip state: Some("script") / Some("style") while inside one
    let mut skip_until: Option<&'static str> = None;

    let flush = |cur: &mut String, lines: &mut Vec<String>| {
        let t = cur.split_whitespace().collect::<Vec<_>>().join(" ");
        if !t.is_empty() && lines.len() < MAX_LINES {
            let mut line = t;
            if line.len() > MAX_LINE_CHARS {
                // cut on a char boundary — never mid-UTF-8
                let mut cut = MAX_LINE_CHARS;
                while !line.is_char_boundary(cut) {
                    cut -= 1;
                }
                line.truncate(cut);
                line.push('…');
            }
            lines.push(line);
        }
        cur.clear();
    };

    while i < bytes.len() {
        if bytes[i] == b'<' {
            // find the tag end
            let close = match html[i..].find('>') {
                Some(off) => i + off,
                None => break,
            };
            let raw = &html[i + 1..close];
            let inner = raw.trim_start_matches('/').trim();
            let name_end = inner
                .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
                .unwrap_or(inner.len());
            let name = inner[..name_end].to_ascii_lowercase();
            let closing = raw.starts_with('/');

            if let Some(skip) = skip_until {
                // only the matching close tag ends the skip
                if closing && name == skip {
                    skip_until = None;
                }
                i = close + 1;
                continue;
            }

            match name.as_str() {
                "script" if !closing => skip_until = Some("script"),
                "style" if !closing => skip_until = Some("style"),
                "title" => in_title = !closing,
                "a" if !closing => {
                    // href extraction — the numbered link lane
                    if links.len() < MAX_LINKS {
                        let lower = raw.to_ascii_lowercase();
                        if let Some(hp) = lower.find("href") {
                            let rest = &raw[hp..];
                            if let Some(q) = rest.find(['"', '\'']) {
                                let quote = rest.as_bytes()[q] as char;
                                let after = &rest[q + 1..];
                                if let Some(qe) = after.find(quote) {
                                    let href = after[..qe].trim();
                                    if !href.is_empty()
                                        && !href.starts_with('#')
                                        && !href.starts_with("javascript:")
                                    {
                                        links.push(href.to_string());
                                        // trailing space too — the annotation must never
                                        // fuse with the link text ("[1]here" is a lie)
                                        cur.push_str(&format!(" [{}] ", links.len()));
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            if is_block_tag(&name) {
                flush(&mut cur, &mut lines);
            }
            i = close + 1;
            continue;
        }
        // text content
        let next_lt = html[i..].find('<').map(|o| i + o).unwrap_or(html.len());
        let chunk = &html[i..next_lt];
        if skip_until.is_none() {
            if in_title {
                title.push_str(chunk);
            } else {
                cur.push_str(chunk);
                cur.push(' ');
            }
        }
        i = next_lt;
    }
    flush(&mut cur, &mut lines);

    // decode entities line-by-line (after structure, before display)
    let mut doc_lines: Vec<String> = lines.into_iter().map(|l| decode_entities(&l)).collect();

    // the numbered link ledger — appended as page tail, terminal style
    if !links.is_empty() && doc_lines.len() < MAX_LINES {
        doc_lines.push(String::new());
        doc_lines.push(format!("— {} links —", links.len()));
        for (n, l) in links.iter().enumerate() {
            if doc_lines.len() >= MAX_LINES {
                break;
            }
            doc_lines.push(format!("[{}] {}", n + 1, l));
        }
    }
    if doc_lines.is_empty() {
        // felt-truth: an empty document renders as the truth, not as blank
        doc_lines.push(format!("(no visible text at {url})"));
    }

    PageDoc {
        title: decode_entities(title.trim()),
        lines: doc_lines,
        links,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_and_text_extracted() {
        let d = parse_document(
            "<html><head><title>Tort&auml;? No — Tort&amp;a</title></head><body><h1>Hello</h1><p>world &amp; peace</p></body></html>",
            "https://x.test",
        );
        assert_eq!(d.title, "Tort&auml;? No — Tort&a");
        assert!(d.lines.iter().any(|l| l == "Hello"));
        assert!(d.lines.iter().any(|l| l == "world & peace"));
    }

    #[test]
    fn scripts_and_styles_stripped() {
        let d = parse_document(
            "<body><script>var x = 'EVIL';</script><style>.a{color:red}</style><p>clean</p></body>",
            "u",
        );
        assert!(d.lines.iter().any(|l| l == "clean"));
        assert!(!d.lines.iter().any(|l| l.contains("EVIL")));
        assert!(!d.lines.iter().any(|l| l.contains("color")));
    }

    #[test]
    fn links_are_numbered_and_ledgered() {
        let d = parse_document(
            "<p>go <a href=\"https://a.test\">here</a> or <a href='/rel'>there</a></p>",
            "u",
        );
        assert_eq!(d.links, vec!["https://a.test", "/rel"]);
        assert!(d.lines.iter().any(|l| l.contains("[1] https://a.test")));
        assert!(d.lines.iter().any(|l| l.contains("[2] /rel")));
        // the inline annotation rides the text line
        assert!(d.lines.iter().any(|l| l.contains("go [1] here or [2] there")));
    }

    #[test]
    fn caps_hold_and_empty_is_honest() {
        // line cap
        let mut big = String::new();
        for i in 0..2000 {
            big.push_str(&format!("<p>line {i}</p>"));
        }
        let d = parse_document(&big, "u");
        assert!(d.lines.len() <= MAX_LINES);
        // honest empty
        let e = parse_document("<body><script>x</script></body>", "https://empty.test");
        assert_eq!(e.lines, vec!["(no visible text at https://empty.test)"]);
    }
}
