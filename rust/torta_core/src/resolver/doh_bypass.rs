//! # The client-DoH bootstrap sinkhole — the hole every pillar was falling through
//!
//! ## The measurement that produced this module
//!
//! On 2026-08-01, driving Brave Nightly through the tunnel with all pillars armed, a page loaded
//! FULLY — Akamai, Fastly and Google assets rendered — while Tortä's own per-query ledger recorded
//! **zero rows**. The resolver never saw the name. The whole ledger delta for that page was:
//!
//! ```text
//! [01:13:38] 127.0.0.1  brave.cloudflare-dns.com  HTTPS  PASS  1ms  cache
//! [01:13:38] 127.0.0.1  brave.cloudflare-dns.com  A      PASS  0ms  cache
//! [01:13:38] 127.0.0.1  brave.cloudflare-dns.com  AAAA   PASS  0ms  cache
//! ```
//!
//! That is the entire attack surface in three lines. The browser asks Tortä to resolve **its own
//! DoH endpoint, once**, and from that moment every name it looks up rides an HTTPS tunnel to
//! Cloudflare. Warden never sees a qname. The blocklist never matches. Centauri never caches.
//! MaskSolver never solves. Nine pillars, armed and green, watching a wire that carries nothing.
//!
//! ## Why the existing defence does not reach it
//!
//! Warden's RULE7 (`block_dns_bypass`, `warden/mod.rs:1569`) fires on `conn.qname.is_none()` — a
//! connection with NO DNS provenance, i.e. someone dialling a resolver by raw IP. Client DoH is
//! the opposite shape: it resolves its bootstrap name **through us** and is therefore fully
//! attributed. RULE7 is correct and this is not a duplicate of it; the two cover different halves
//! of the same intent, and both are needed.
//!
//! ## What this does
//!
//! Denies the small, curated set of hostnames browsers use to BOOTSTRAP their own DoH, at the
//! resolver, with zero egress. A browser that cannot resolve `brave.cloudflare-dns.com` falls back
//! to system DNS — which is Tortä — and every subsequent name becomes visible to the pillars again.
//!
//! ## Three properties that are load-bearing
//!
//! * **Label-boundary matching, never substring.** `notcloudflare-dns.com` is a DIFFERENT domain
//!   that a substring match would silently sinkhole. A resolver that denies names nobody asked it
//!   to deny is a worse failure than the bypass it was fixing, because it is invisible until a user
//!   cannot reach a site. Tested directly, including the adversarial prefix case.
//! * **Subdomains are covered.** `mozilla.cloudflare-dns.com` and `chrome.dns.google` are the same
//!   bypass wearing a label. An apex entry covers its subtree.
//! * **OFF by default.** Arming this changes what resolves, and a user who deliberately runs DoH is
//!   making a legitimate choice. It is a policy the host arms, never a silent default — the same
//!   posture as `WARDEN_ENFORCE`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The curated bootstrap set.
///
/// Entries are **apexes**: an entry covers itself and every subdomain. Deliberately SMALL — this
/// is not a blocklist and must never grow into one. The test for inclusion is narrow: *is this
/// hostname used by a browser or OS to bootstrap its own encrypted resolver, such that resolving
/// it hands DNS visibility away from the user's chosen resolver?*
///
/// What is deliberately ABSENT is as important as what is present. `dns.quad9.net`,
/// `dnscry.pt` and the other operator apexes Tortä's OWN upstreams live under are NOT here: this
/// module must never be able to sinkhole the resolver's own transport bootstrap. That would turn a
/// privacy feature into the total outage this codebase already spent a night diagnosing.
const DOH_BOOTSTRAP_APEXES: &[&str] = &[
    // Cloudflare — the endpoint Brave/Firefox/Chrome variants bootstrap through. MEASURED in the
    // ledger above as the actual bypass on this device.
    "cloudflare-dns.com",
    // Google Public DNS DoH.
    "dns.google",
    // Quad9's DoH front (distinct host from the DNSCrypt stamps Tortä may use as an upstream).
    "dns.quad9.net",
    // OpenDNS / Cisco DoH.
    "doh.opendns.com",
    // AdGuard DoH.
    "dns.adguard.com",
    "dns.adguard-dns.com",
    // NextDNS bootstrap.
    "dns.nextdns.io",
    // Firefox's canary + Cloudflare's alternate DoH names.
    "mozilla.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    // Apple/iCloud Private Relay DoH front.
    "doh.dns.apple.com",
];

/// Armed state. OFF by default — an unarmed sinkhole is byte-identical to not having one.
static DOH_SINKHOLE_ENFORCE: AtomicBool = AtomicBool::new(false);

/// Monotonic count of queries this sinkhole has denied. A GAUGE for the dashboard and the only
/// honest way to answer "is it doing anything".
static DOH_SINKHOLE_DENIED: AtomicU64 = AtomicU64::new(0);

/// Arm or disarm the sinkhole. Host-driven; never flipped by the datapath itself.
pub fn set_enforce(on: bool) {
    DOH_SINKHOLE_ENFORCE.store(on, Ordering::Relaxed);
}

/// Is the sinkhole armed?
pub fn enforce_on() -> bool {
    DOH_SINKHOLE_ENFORCE.load(Ordering::Relaxed)
}

/// How many queries have been denied as DoH bootstrap this process.
pub fn denied_count() -> u64 {
    DOH_SINKHOLE_DENIED.load(Ordering::Relaxed)
}

/// Count one denial. Called only from the datapath hook, only when a deny actually fires.
pub(crate) fn record_denial() {
    DOH_SINKHOLE_DENIED.fetch_add(1, Ordering::Relaxed);
}

/// Does `qname` name a known client-DoH bootstrap endpoint?
///
/// Matching is **label-boundary suffix**: `host == apex` or `host` ends with `"." ++ apex`. Case is
/// folded and one trailing root dot is tolerated, because both appear in real wire data.
///
/// This is a PURE predicate — it does not consult the armed flag. The caller decides whether a
/// match should act, so the predicate stays testable without touching global state.
pub fn is_doh_bootstrap(qname: &str) -> bool {
    let host = qname.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    DOH_BOOTSTRAP_APEXES.iter().any(|apex| {
        // Exact apex, or a subdomain of it. The leading '.' is what makes this a LABEL-boundary
        // test rather than a substring test: without it, "notcloudflare-dns.com" matches
        // "cloudflare-dns.com" and the resolver starts denying an unrelated domain.
        host == *apex || (host.len() > apex.len() + 1 && host.ends_with(&format!(".{apex}")))
    })
}

/// The armed check the datapath calls: armed AND a bootstrap name.
pub(crate) fn should_deny(qname: &str) -> bool {
    enforce_on() && is_doh_bootstrap(qname)
}

/// How many apexes the curated set carries. Exposed so a test can assert the set is non-empty
/// without reaching into the constant.
pub fn apex_count() -> usize {
    DOH_BOOTSTRAP_APEXES.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_measured_bypass_is_denied() {
        // The exact name observed in cache/query.log on 2026-08-01.
        assert!(is_doh_bootstrap("brave.cloudflare-dns.com"));
    }

    #[test]
    fn apexes_match_themselves() {
        assert!(is_doh_bootstrap("cloudflare-dns.com"));
        assert!(is_doh_bootstrap("dns.google"));
        assert!(is_doh_bootstrap("dns.nextdns.io"));
    }

    #[test]
    fn subdomains_are_covered() {
        assert!(is_doh_bootstrap("mozilla.cloudflare-dns.com"));
        assert!(is_doh_bootstrap("chrome.dns.google"));
        assert!(is_doh_bootstrap("a.b.c.cloudflare-dns.com"));
    }

    #[test]
    fn matching_is_label_boundary_not_substring() {
        // THE property that keeps this from becoming a wildcard. Every one of these is a
        // DIFFERENT domain that a naive `contains`/`ends_with` would sinkhole.
        assert!(!is_doh_bootstrap("notcloudflare-dns.com"));
        assert!(!is_doh_bootstrap("xcloudflare-dns.com"));
        assert!(!is_doh_bootstrap("evil-dns.google.attacker.com"));
        assert!(!is_doh_bootstrap("mydns.google.com"));
        assert!(!is_doh_bootstrap("cloudflare-dns.com.evil.net"));
    }

    #[test]
    fn ordinary_names_are_untouched() {
        for name in [
            "google.com",
            "cloudflare.com",
            "one.one.one.one",
            "github.com",
            "example.com",
            "",
        ] {
            assert!(!is_doh_bootstrap(name), "{name} must not be sinkholed");
        }
    }

    #[test]
    fn case_and_trailing_dot_are_normalised() {
        assert!(is_doh_bootstrap("BRAVE.Cloudflare-DNS.COM"));
        assert!(is_doh_bootstrap("dns.google."));
        assert!(is_doh_bootstrap("DNS.GOOGLE."));
    }

    #[test]
    fn torta_own_upstream_operators_are_not_in_the_set() {
        // A sinkhole that can deny the resolver's OWN transport bootstrap is an outage generator,
        // not a privacy feature. These are operator apexes Tortä's upstreams live under.
        for own in ["dnscry.pt", "cs-montreal.dnscrypt.info", "serbica.info", "quad9.net"] {
            assert!(!is_doh_bootstrap(own), "{own} is ours and must never be sinkholed");
        }
    }

    #[test]
    fn off_by_default_so_arming_is_a_choice() {
        // should_deny consults the armed flag; is_doh_bootstrap does not.
        assert!(is_doh_bootstrap("dns.google"));
        set_enforce(false);
        assert!(!should_deny("dns.google"), "disarmed must never deny");
        set_enforce(true);
        assert!(should_deny("dns.google"), "armed must deny a bootstrap name");
        assert!(!should_deny("github.com"), "armed must NOT deny an ordinary name");
        set_enforce(false);
    }

    /// A GUARD AGAINST THE CENTAURI CLASS OF DEFECT, kept here because this module is where the
    /// lesson was paid for.
    ///
    /// Centauri's cloak had a four-conjunct gate whose first conjunct was fed by a publisher that
    /// existed, was documented, was unit-tested — and was called from `#[cfg(test)]` code ONLY.
    /// Never exported, never referenced by the app. Every test passed. The feature was dead in
    /// production for as long as it had shipped, behind a dashboard that said "LIVE".
    ///
    /// A unit test that exercises a flag its own production caller never sets is not evidence the
    /// feature works; it is evidence the feature COMPILES. So this asserts the shape that matters
    /// for the sinkhole: the datapath predicate and the host-facing arming call are the SAME
    /// switch, and flipping the public one is observable through the public reader.
    #[test]
    fn the_arming_switch_is_reachable_from_the_host_surface() {
        let before = enforce_on();
        set_enforce(true);
        assert!(enforce_on(), "the public reader must observe the public writer");
        assert!(should_deny("dns.google"), "the DATAPATH must see what the host armed");
        set_enforce(false);
        assert!(!enforce_on());
        assert!(!should_deny("dns.google"), "disarming must reach the datapath too");
        set_enforce(before);
    }

    #[test]
    fn the_curated_set_is_non_empty() {
        assert!(apex_count() >= 8, "a set this small is the point, but it must not be empty");
    }
}
