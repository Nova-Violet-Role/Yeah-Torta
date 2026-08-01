/*
    This file is part of Yeah! Tortä.
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2
    Copyright 2026 Saimonokuma.
*/

//! UI TEXT — the canonical user-facing string catalog. The repo is `.xml`-free: user-facing copy rides
//! the trio (Rust holds it here → UniFFI bridges it → Kotlin-inject-wired Kotlin renders it), NEVER an
//! Android `strings.xml` resource (now forbidden). This is the bulk migration that follows
//! [`crate::inu::inu_rearm_notice`] — every string the surviving Android layer (notifications, tiles,
//! dialogs, services, the Academic-Wall education corpus) used to read via `getString(R.string.*)` now
//! reads via [`torta_text`] with the SAME key it had as a resource name.
//!
//! Format strings keep their Java/Kotlin `%1$s` / `%s` placeholders verbatim — the Kotlin call site does
//! `tortaText("key").format(arg)` exactly as it used to do `getString(R.string.key, arg)`.
//!
//! Unknown keys return the empty string (fail-open: a missing label degrades to blank, never a crash).

/// Look up a user-facing string by its (former Android resource) key. See the module doc for the
/// `.xml`-free doctrine. Unknown keys yield `""`.
#[uniffi::export]
pub fn torta_text(key: String) -> String {
    match key.as_str() {
        "action_mode_dialog_locked" => "Control Locked",
        "app_name" => "Yeah! Tortä",
        "ask_later" => "Ask later",
        "ask_save_changes" => "Do you want to save the changes?",
        "buy_premium_gp" => "Yeah! Tortä Project seeks your assistance. Press OK to purchase premium features.",
        "cancel" => "Cancel",
        "cancel_download" => "CANCEL DOWNLOAD",
        "connectivity_check" => "Internet connectivity check",
        "dialog_send_crash_report" => "A crash report has been discovered. Want to send it to the developer to make Tortä better?",
        "dns_rule_add_url" => "Add URL",
        "dnscrypt_update_text" => "Version %1$s was released upstream. Update Yeah! Tortä (via F-Droid) to get the newer dnscrypt-proxy.",
        "dnscrypt_update_title" => "dnscrypt-proxy update available",
        "dnsmasq_editor_unavailable" => "The native engine is not reachable — nothing was saved.",
        "donate" => "Donate",
        "donate_project" => "Yeah! Tortä Project seeks your assistance. Please visit the donation page or enter the premium code you've already received.",
        "dont_show" => "Don't show",
        "edu_arpa_geek" => "Today: the reverse-DNS zones (<tt>.in-addr.arpa</tt> / <tt>.ip6.arpa</tt>) are EXEMPTED from rebind defense so legitimate PTR lookups about private space still work — the app stays rebind-aware without false positives. Not yet: proactively blocking PTR lookups of your OWN private IPs from leaving to the public resolver (so it can never reverse-map your LAN). That proactive PTR-leak prevention is planned — tracked as #91. We say what is live, not what is promised.",
        "edu_arpa_simple" => "Tortä is rebind-aware on reverse-DNS lookups today; fully stopping reverse lookups of your private addresses from leaving is on the way (#91).",
        "edu_arpa_status" => "Partly live — full PTR-leak prevention coming (#91)",
        "edu_arpa_title" => "Reverse-DNS (.arpa) awareness",
        "edu_beast_geek" => "The Beast is a TCP-inspired congestion-control plus active-queue-management layer that runs ALONGSIDE DNSCrypt: it measures relays, picks the fastest, and paces probes (CAKE shaping + YeAH-style control) so DNS feels snappy without flooding the network. It is toggleable — turn it off here to keep encrypted DNSCrypt without the engine. It only adds speed; it never weakens the encryption.",
        "edu_beast_simple" => "The CAKE·YeAH \"Beast\" picks the fastest relay and paces your probes — speed alongside encrypted DNS.",
        "edu_beast_status" => "Active now (toggleable)",
        "edu_beast_title" => "The Beast — CAKE · YeAH",
        "edu_blocklist_geek" => "Blocked domains live in a reversed-label trie (<tt>com·google·www</tt>), so blocking one name blocks every subdomain beneath it in a single prefix walk — a fraction of the RAM and battery a giant string set would cost. When a query matches, Tortä synthesizes the answer LOCALLY as an NXDOMAIN (RCODE 3) — the question is echoed back as \"no such domain\" without a single byte going out to any resolver. No egress, no tracker contact.",
        "edu_blocklist_simple" => "Blocked ad and tracker domains are answered right on your phone — the request never leaves the device.",
        "edu_blocklist_status" => "Active now",
        "edu_blocklist_title" => "Local ad & tracker blocking",
        "edu_centauri_geek" => "Centauri is opt-in and OFF by default — an untouched install never opens it. When you enable it, the offline Haskell brain signs the catalog (the trust root) and any cached asset is verified hash-first against that signature before it is trusted. Not yet: the in-app loopback that actually SERVES the verified cache so the upstream CDN sees at most one request ever — that bind/serve seam is deferred and lands in #92. Today it is verify + status only; we never claim it is serving.",
        "edu_centauri_simple" => "An opt-in local mirror that verifies common web files by their content hash first; serving them locally is landing soon (#92).",
        "edu_centauri_status" => "Opt-in (off by default); local serving lands in #92",
        "edu_centauri_title" => "Centauri local mirror",
        "edu_dnscrypt_geek" => "DNSCrypt is the foundation: every lookup is encrypted AND authenticated end-to-end with the resolver, so a network observer can't read your queries and can't forge the answers. You can require servers that satisfy a privacy matrix — no-log (must not log your queries), DNSSEC (cryptographically validated answers), and no-filter (no hidden blacklist) — and DoH/ODoH plus relay-chaining add anonymity. It is the one default-ON privacy layer every other feature composes inside.",
        "edu_dnscrypt_simple" => "Your DNS lookups travel encrypted and authenticated, so your ISP can't read or tamper with which sites you ask for.",
        "edu_dnscrypt_status" => "Active now",
        "edu_dnscrypt_title" => "DNSCrypt — encrypted DNS",
        "edu_doh3_geek" => "When the DoH3 preference is on (default), the app patches <tt>http3 = true</tt> into the DNSCrypt config at start, so DNS-over-HTTPS rides QUIC (HTTP/3, RFC 9114) instead of TCP. QUIC keeps the encryption of DoH while shrugging off packet loss and connection-migration on a phone that hops between Wi-Fi and mobile data. Turn it off and the line is commented out (never deleted), falling back to the standard transport.",
        "edu_doh3_simple" => "Tortä can send DNS over HTTP/3 (QUIC) — encrypted, and quicker on flaky mobile networks.",
        "edu_doh3_status" => "Active now",
        "edu_doh3_title" => "DoH3 — encrypted and fast",
        "edu_ignore_system_dns_geek" => "At startup the app sets <tt>ignore_system_dns = true</tt> (default ON), so DNSCrypt does not use the system DNS settings to bootstrap. Instead it dials a fixed bootstrap resolver (Quad9, 9.9.9.9) to reach the encrypted servers — so the bootstrap itself never leaks to your ISP or the system DNS. You can turn it off; we then faithfully write <tt>ignore_system_dns = false</tt>.",
        "edu_ignore_system_dns_simple" => "From the very first lookup, Tortä ignores your phone's built-in DNS so your provider never sees which sites you visit.",
        "edu_ignore_system_dns_status" => "Active now",
        "edu_ignore_system_dns_title" => "No leak to your ISP",
        "edu_rebind_geek" => "For answers to PUBLIC names, the Guardian classifies every returned IP: any RFC1918 (<tt>10/8</tt>, <tt>172.16/12</tt>, <tt>192.168/16</tt>), loopback (<tt>127/8</tt>, <tt>::1</tt>), link-local (<tt>169.254/16</tt>, <tt>fe80::/10</tt>) or IPv6 unique-local (<tt>fc00::/7</tt>) address is the rebind signal (it even re-classifies IPv4-mapped IPv6 to catch the smuggling trick). Genuine LAN names (<tt>.local</tt>, <tt>.lan</tt>, split-horizon) are exempt, so there are no false positives. By default it OBSERVES (counts) these; under Expert enforcement it DROPS them — the datapath simply falls through to the encrypted resolver, never caching or returning the poisoned answer.",
        "edu_rebind_simple" => "Tortä spots a public website that secretly points to a private address on your network — a classic DNS-rebind attack — and flags it.",
        "edu_rebind_status" => "Active now",
        "edu_rebind_title" => "Rebind / poison defense",
        "edu_rotation_geek" => "Rotation (default OFF — an untouched install never rotates) periodically swaps the upstream resolver pool on a 12-hour cadence. Candidates are trust-filtered on their resolver-stamp properties, excluded for operator-family overlap (real diversity, not just a different name), and ranked by live RTT measured on the same ping the app already shows. The swap is a single atomic pool pointer-change that fails SAFE — if there is no diverse, trusted, reachable candidate this cycle it simply keeps the current set, so rotation can never break a live resolution.",
        "edu_rotation_simple" => "Turn on rotation and Tortä keeps changing which encrypted resolver answers you, so no single one ever sees your whole browsing pattern.",
        "edu_rotation_status" => "Active now (off by default)",
        "edu_rotation_title" => "Resolver rotation",
        "free_version" => "Free",
        "helper_dialog_title" => "Info",
        "helper_dnscrypt_private_dns" => "Please turn off \"Private DNS\" in Android network settings. This option interferes with Tortä.",
        "helper_dnscrypt_proxy_gsm" => "Please disable proxy in Android Mobile network APN settings. This option interferes with Tortä.",
        "helper_dnscrypt_proxy_wifi" => "Please disable proxy in Android WiFi network settings. This option interferes with Tortä.",
        "main_fragment_button_start" => "START",
        "main_fragment_button_stop" => "STOP",
        "menu_wire_cake_inu" => "Wireless Debug (no-root)",
        "notification_arp_spoofing" => "ARP spoofing detected!",
        "notification_channel_auxiliary" => "Auxiliary notifications",
        "notification_channel_root" => "Root commands notification",
        "notification_channel_services" => "Yeah! Tortä protection",
        "notification_channel_update" => "Update notifications",
        "notification_connecting" => "Connecting…",
        "notification_dns_rebinding_text" => "Potential DNS Rebinding Attack Detected! Site %s has been blocked.",
        "notification_dns_rebinding_title" => "DNS rebinding",
        "notification_exclude_bat_optimisation_title" => "Stop optimizing battery usage?",
        "notification_exclude_data_restriction_message" => "Please allow background data usage and allow data usage while Data saver is on. This is essential for a smooth online experience.",
        "notification_exclude_data_restriction_title" => "Disable network data saver?",
        "notification_exec_root_commands" => "Executing Root commands…",
        "notification_internet_blocked_message" => "Internet blocked due to the Kill switch. Start DNSCrypt to allow the connection. Or disable the Kill switch in Common Settings.",
        "notification_rogue_dhcp" => "Rogue DHCP detected!",
        "notification_text" => "DNSCrypt is protected. Don't hide.",
        "notification_waiting_network" => "Waiting for network…",
        "notifications_permission_rationale_message" => "Notifications are essential for displaying important information about the app's operation, app control, and detected attacks. Would you like to allow notifications for Tortä?",
        "ok" => "OK",
        "please_wait" => "Please wait…",
        "pref_common_kill_switch" => "Kill switch",
        "pref_common_notification_helper" => "Please exclude Yeah! Tortä from Android battery optimization to prevent the system from terminating DNSCrypt at any time. Some special systems, such as MIUI, may require additional steps.",
        "pref_fast_unlock_host_wrong" => "Wrong host name!",
        "premium" => "Premium version",
        "premium_version" => "Premium",
        "refunded_version" => "Refunded",
        "reset_settings_title" => "Attention",
        "tile_dialog_over_three_tiles_message" => "You have added more than 3 tiles to Quick Settings. Please leave only 3. Adding more than 3 tiles can cause issues with app control.",
        "toast_arp_detection_not_supported" => "ARP spoofing detection is not supported for your device!",
        "torta_slice_toast" => "now the Tortä is screaming YEAH!!",
        "tvDNSDefaultLog" => "DNSCrypt-proxy version",
        "tvDNSRunning" => "DNSCrypt Running",
        "tvDNSStarting" => "DNSCrypt Starting",
        "tvDNSStop" => "DNSCrypt Stopped",
        "tvDNSStopping" => "DNSCrypt Stopping",
        "update_fault" => "Update fault.",
        "update_installed" => "Updates were installed.",
        "update_interrupt_notification" => "Download was stopped",
        "update_notification" => "Downloading file",
        "vpn_mode_error" => "VPN mode error!",
        "vpn_mode_off" => "VPN mode is off",
        "wd_err_not_loopback" => "Pairing endpoint is not on this device (must be 127.0.0.1) — refused for safety.",
        "wd_notif_baked_body" => "Wireless Debug paired — your no-root powers are granted.",
        "wd_notif_baked_title" => "The Soft-Cäke is now officially baked 🍰",
        "wd_notif_channel" => "Wireless Debug pairing",
        "wd_notif_enter_code" => "Enter pairing code",
        "wd_notif_failed_title" => "Pairing failed",
        "wd_notif_found_body" => "Tap “Enter pairing code” and type the 6-digit code shown on your phone.",
        "wd_notif_found_title" => "Pairing service found",
        "wd_notif_retry" => "Retry",
        "wd_notif_searching_body" => "Turn on “Pair device with pairing code” in Wireless debugging.",
        "wd_notif_searching_title" => "Looking for the pairing service…",
        "wd_notif_slice_btn" => "Bring me a slice of tortä",
        "wd_notif_stop" => "Stop",
        "wd_notif_working_body" => "Pairing with this device and applying no-root powers.",
        "wd_notif_working_step" => "Granting: %1$s",
        "wd_notif_working_title" => "Pairing & granting…",
        "wrong" => "Something went wrong!",
        _ => "",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_keys_resolve_and_unknown_is_empty() {
        assert_eq!(torta_text("cancel".to_string()), "Cancel");
        assert_eq!(torta_text("ask_later".to_string()), "Ask later");
        assert_eq!(torta_text("app_name".to_string()), "Yeah! Tortä");
        // format string keeps its placeholder verbatim
        assert_eq!(torta_text("wd_notif_working_step".to_string()), "Granting: %1$s");
        // fail-open: unknown key -> empty, never a panic
        assert_eq!(torta_text("no_such_key_zzz".to_string()), "");
    }
}
