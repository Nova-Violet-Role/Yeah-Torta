/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! ---- #60F THE SPECIALS — the userscript + extension engine over the
//! assimilated renderer: a Tampermonkey-class userscript host (GM_* surface
//! law, @match / @run-at) plus a Chrome-compatible WebExtension (MV2/MV3)
//! install lane. FELT-TRUTH LAW: nothing is EVER claimed installed unless its
//! bytes were genuinely parsed from real text; every rejection carries its
//! real reason; counters grow only on genuinely taken decisions. The manifest
//! reader is a labeled SNIFFER (a scanner, not a full JSON engine) — it never
//! pretends otherwise. ----

/// The GM_* surface law — the APIs the host GRANTS to userscripts. This is the
/// grant list, not an execution claim: `GM_xmlhttpRequest` rides the Tortä
/// socket law (Beast QoS + Centauri + Underground) when execution lands.
pub const GM_SURFACE: &[&str] = &[
    "GM_getValue",
    "GM_setValue",
    "GM_deleteValue",
    "GM_listValues",
    "GM_addStyle",
    "GM_xmlhttpRequest",
    "GM_openInTab",
    "GM_registerMenuCommand",
];

/// `@run-at` — when the host injects. Tampermonkey's honest default is
/// `document-idle`; an absent or unknown value falls back to it (documented,
/// never invented).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunAt {
    DocumentStart,
    DocumentEnd,
    DocumentIdle,
}

/// A userscript genuinely parsed from a `// ==UserScript==` header block.
#[derive(Debug, Clone)]
pub struct UserScript {
    pub name: String,
    /// "" when the header omits `@version` — never invented.
    pub version: String,
    pub matches: Vec<String>,
    pub run_at: RunAt,
}

impl UserScript {
    /// Parse the Tampermonkey header block. Rejections carry the real reason:
    /// no header block, no `@name`, or no `@match`/`@include` at all.
    pub fn parse(src: &str) -> Result<Self, String> {
        let mut in_block = false;
        let mut saw_block = false;
        let mut name = String::new();
        let mut version = String::new();
        let mut matches: Vec<String> = Vec::new();
        let mut run_at = RunAt::DocumentIdle;
        for line in src.lines() {
            let l = line.trim();
            let Some(body) = l.strip_prefix("//") else { continue };
            let body = body.trim();
            if body == "==UserScript==" {
                in_block = true;
                saw_block = true;
                continue;
            }
            if body == "==/UserScript==" {
                in_block = false;
                continue;
            }
            if !in_block {
                continue;
            }
            let Some(rest) = body.strip_prefix('@') else { continue };
            let (key, val) = rest
                .split_once(char::is_whitespace)
                .map(|(k, v)| (k, v.trim()))
                .unwrap_or((rest, ""));
            match key {
                "name" if !val.is_empty() => name = val.to_string(),
                "version" => version = val.to_string(),
                "match" | "include" if !val.is_empty() => matches.push(val.to_string()),
                "run-at" => {
                    run_at = match val {
                        "document-start" => RunAt::DocumentStart,
                        "document-end" => RunAt::DocumentEnd,
                        _ => RunAt::DocumentIdle,
                    }
                }
                _ => {}
            }
        }
        if !saw_block {
            return Err("no ==UserScript== header block".into());
        }
        if name.is_empty() {
            return Err("header lacks @name".into());
        }
        if matches.is_empty() {
            return Err("header lacks @match".into());
        }
        Ok(Self { name, version, matches, run_at })
    }

    /// Genuinely evaluated match law — true only when one of the script's
    /// patterns really matches `url`.
    pub fn matches_url(&self, url: &str) -> bool {
        self.matches.iter().any(|p| match_pattern(p, url))
    }
}

/// Chrome match-pattern law: `<scheme>://<host>/<path>` where scheme `*` means
/// http/https, host may be `*` or `*.suffix`, and the path is a `*` glob.
/// `<all_urls>` matches any http/https URL. Anything malformed matches nothing
/// — a non-decision, never a grant.
pub fn match_pattern(pattern: &str, url: &str) -> bool {
    let (us, urest) = match url.split_once("://") {
        Some(x) => x,
        None => return false,
    };
    if pattern == "<all_urls>" {
        return us == "http" || us == "https";
    }
    let (ps, prest) = match pattern.split_once("://") {
        Some(x) => x,
        None => return false,
    };
    let scheme_ok = match ps {
        "*" => us == "http" || us == "https",
        s => s == us,
    };
    if !scheme_ok {
        return false;
    }
    let (ph, ppath) = match prest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (prest, String::from("/")),
    };
    let (uh, upath) = match urest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (urest, String::from("/")),
    };
    let host_ok = if ph == "*" {
        true
    } else if let Some(suf) = ph.strip_prefix("*.") {
        uh == suf || uh.ends_with(&format!(".{suf}"))
    } else {
        ph == uh
    };
    host_ok && glob_match(&ppath, &upath)
}

/// Plain `*` glob with iterative backtracking — no regex engine, no surprises.
fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '*' || p[pi] == t[ti]) {
            if p[pi] == '*' {
                star = pi;
                mark = ti;
                pi += 1;
            } else {
                pi += 1;
                ti += 1;
            }
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Manifest generation — sniffed from `manifest_version`, never assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVersion {
    Mv2,
    Mv3,
}

/// A WebExtension whose manifest was genuinely sniffed from real bytes.
#[derive(Debug, Clone)]
pub struct WebExtension {
    pub name: String,
    /// "" when the manifest omits `version` — never invented.
    pub version: String,
    pub manifest_version: ManifestVersion,
    pub permissions: Vec<String>,
}

impl WebExtension {
    /// Sniff a Chrome manifest.json. Labeled law: this is a SCANNER for the
    /// fields the lane needs — `manifest_version` (2/3 only), `name`,
    /// `version`, `permissions` — not a full JSON engine.
    pub fn parse(manifest_json: &str) -> Result<Self, String> {
        let mv = json_num_field(manifest_json, "manifest_version")
            .ok_or_else(|| String::from("manifest_version missing"))?;
        let manifest_version = match mv {
            2 => ManifestVersion::Mv2,
            3 => ManifestVersion::Mv3,
            other => return Err(format!("manifest_version {other} unsupported")),
        };
        let name = json_str_field(manifest_json, "name")
            .ok_or_else(|| String::from("name missing"))?;
        let version = json_str_field(manifest_json, "version").unwrap_or_default();
        let permissions = json_str_array(manifest_json, "permissions");
        Ok(Self { name, version, manifest_version, permissions })
    }
}

fn json_str_field(src: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = src.find(&needle)?;
    let rest = &src[at + needle.len()..];
    let colon = rest.find(':')?;
    let rest = rest[colon + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut esc = false;
    for c in rest.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == '"' {
            return Some(out);
        } else {
            out.push(c);
        }
    }
    None
}

fn json_num_field(src: &str, key: &str) -> Option<u32> {
    let needle = format!("\"{key}\"");
    let at = src.find(&needle)?;
    let rest = &src[at + needle.len()..];
    let colon = rest.find(':')?;
    let digits: String = rest[colon + 1..]
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn json_str_array(src: &str, key: &str) -> Vec<String> {
    let needle = format!("\"{key}\"");
    let Some(at) = src.find(&needle) else { return Vec::new() };
    let rest = &src[at + needle.len()..];
    let Some(open) = rest.find('[') else { return Vec::new() };
    let Some(close_rel) = rest[open..].find(']') else { return Vec::new() };
    let body = &rest[open + 1..open + close_rel];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut esc = false;
    for c in body.chars() {
        if in_str {
            if esc {
                cur.push(c);
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
                out.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        } else if c == '"' {
            in_str = true;
        }
    }
    out
}

/// What one drop-in install attempt really became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    UserScriptIn,
    ExtensionIn,
    Rejected(String),
}

/// The 60F bay — the registry of everything GENUINELY installed. Counters grow
/// only when a real parse decision is taken; the last rejection keeps its real
/// reason for the pane line.
#[derive(Debug, Default)]
pub struct SpecialsBay {
    userscripts: Vec<UserScript>,
    extensions: Vec<WebExtension>,
    rejected: u32,
    last_reject: String,
}

impl SpecialsBay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed real userscript text through the parse law.
    pub fn install_userscript(&mut self, src: &str) -> InstallOutcome {
        match UserScript::parse(src) {
            Ok(us) => {
                self.userscripts.push(us);
                InstallOutcome::UserScriptIn
            }
            Err(e) => {
                self.rejected += 1;
                self.last_reject = e.clone();
                InstallOutcome::Rejected(e)
            }
        }
    }

    /// Feed real manifest bytes through the sniff law.
    pub fn install_extension(&mut self, manifest_json: &str) -> InstallOutcome {
        match WebExtension::parse(manifest_json) {
            Ok(we) => {
                self.extensions.push(we);
                InstallOutcome::ExtensionIn
            }
            Err(e) => {
                self.rejected += 1;
                self.last_reject = e.clone();
                InstallOutcome::Rejected(e)
            }
        }
    }

    pub fn userscripts(&self) -> usize {
        self.userscripts.len()
    }

    pub fn extensions(&self) -> usize {
        self.extensions.len()
    }

    pub fn rejected(&self) -> u32 {
        self.rejected
    }

    pub fn last_reject(&self) -> &str {
        &self.last_reject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_SCRIPT: &str = r#"
// ==UserScript==
// @name     Torta Dark
// @version  1.2
// @match    *://*.example.com/*
// @run-at   document-start
// ==/UserScript==
console.log('hi');
"#;

    #[test]
    fn userscript_parses_real_header() {
        let us = UserScript::parse(GOOD_SCRIPT).expect("parses");
        assert_eq!(us.name, "Torta Dark");
        assert_eq!(us.version, "1.2");
        assert_eq!(us.run_at, RunAt::DocumentStart);
        assert_eq!(us.matches.len(), 1);
    }

    #[test]
    fn userscript_run_at_defaults_to_idle() {
        let src = "// ==UserScript==\n// @name X\n// @match <all_urls>\n// ==/UserScript==\n";
        let us = UserScript::parse(src).expect("parses");
        assert_eq!(us.run_at, RunAt::DocumentIdle);
        assert_eq!(us.version, "");
    }

    #[test]
    fn userscript_rejections_carry_real_reasons() {
        assert!(UserScript::parse("console.log(1)").unwrap_err().contains("header block"));
        let no_name = "// ==UserScript==\n// @match *://a/*\n// ==/UserScript==\n";
        assert!(UserScript::parse(no_name).unwrap_err().contains("@name"));
        let no_match = "// ==UserScript==\n// @name X\n// ==/UserScript==\n";
        assert!(UserScript::parse(no_match).unwrap_err().contains("@match"));
    }

    #[test]
    fn match_pattern_law_holds() {
        assert!(match_pattern("*://*.example.com/*", "https://sub.example.com/a/b"));
        assert!(match_pattern("*://*.example.com/*", "http://example.com/"));
        assert!(!match_pattern("*://*.example.com/*", "https://evil.com/"));
        assert!(match_pattern("https://one.site/path/*", "https://one.site/path/x"));
        assert!(!match_pattern("https://one.site/path/*", "http://one.site/path/x"));
        assert!(match_pattern("<all_urls>", "https://any.where/x"));
        assert!(!match_pattern("<all_urls>", "ftp://any.where/x"));
        assert!(!match_pattern("garbage", "https://a/"));
    }

    #[test]
    fn manifest_sniff_mv2_and_mv3() {
        let mv3 = r#"{ "manifest_version": 3, "name": "uBlock-ish", "version": "0.9",
                       "permissions": ["storage", "tabs"] }"#;
        let we = WebExtension::parse(mv3).expect("mv3");
        assert_eq!(we.manifest_version, ManifestVersion::Mv3);
        assert_eq!(we.name, "uBlock-ish");
        assert_eq!(we.permissions, vec!["storage".to_string(), "tabs".to_string()]);
        let mv2 = r#"{ "manifest_version": 2, "name": "Old One" }"#;
        let we2 = WebExtension::parse(mv2).expect("mv2");
        assert_eq!(we2.manifest_version, ManifestVersion::Mv2);
        assert_eq!(we2.version, "");
        assert!(we2.permissions.is_empty());
    }

    #[test]
    fn manifest_sniff_rejects_honestly() {
        assert!(WebExtension::parse("{}").unwrap_err().contains("manifest_version"));
        assert!(WebExtension::parse(r#"{ "manifest_version": 9, "name": "X" }"#)
            .unwrap_err()
            .contains("unsupported"));
        assert!(WebExtension::parse(r#"{ "manifest_version": 3 }"#)
            .unwrap_err()
            .contains("name"));
    }

    #[test]
    fn bay_counters_grow_only_on_real_decisions() {
        let mut bay = SpecialsBay::new();
        assert_eq!(bay.install_userscript(GOOD_SCRIPT), InstallOutcome::UserScriptIn);
        assert!(matches!(bay.install_userscript("nope"), InstallOutcome::Rejected(_)));
        assert_eq!(
            bay.install_extension(r#"{ "manifest_version": 3, "name": "N" }"#),
            InstallOutcome::ExtensionIn
        );
        assert_eq!(bay.userscripts(), 1);
        assert_eq!(bay.extensions(), 1);
        assert_eq!(bay.rejected(), 1);
        assert!(bay.last_reject().contains("header block"));
        assert!(GM_SURFACE.contains(&"GM_xmlhttpRequest"));
    }
}
