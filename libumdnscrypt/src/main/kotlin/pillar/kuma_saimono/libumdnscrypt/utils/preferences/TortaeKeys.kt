/*
    SPDX-License-Identifier: AGPL-3.0-or-later OR EUPL-1.2

    Yeah! Tortä
    Copyright 2026 Saimonokuma

    This file is part of Yeah! Tortä, dual-licensed at your option under
    EITHER the GNU Affero General Public License, version 3 or later (see
    agpl-3.0.md), OR the European Union Public Licence, version 1.2 or later
    (see EUPL-LICENSE.txt).

    Distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
    PARTICULAR PURPOSE.
 */

package pillar.kuma_saimono.libumdnscrypt.utils.preferences

/**
 * TortaeKeys — the clean-room ORIGINAL store of the Tortä-authored preference key constants.
 *
 * R3 settings-unify (de-InviZible). These keys are Saimonokuma originals (the CAKE/YeAH engine,
 * the native resolver/Warden seams, the per-upstream Governor + Solver, resolver rotation, the
 * dnsmasq local-DNS pillar, Centauri, the Fortress, no-root Wireless Debug, the #93 blocklist
 * search, and the in-app tips / battery-keepalive surface). They were reimplemented here from the
 * R3 SPEC, not copied or reorganised from any InviZible-derived source, so this file carries the
 * clean Saimonokuma-only notice and joins the Blake2b authorship spine.
 *
 * R3 settings-unify: this file is now the UNIFIED preference-key store. Below the originals it
 * also carries the InviZible-DERIVED legacy key STRINGS (the app shell, Fast/Common/DNSCrypt
 * settings, firewall, VPN, proxy) re-homed BYTE-IDENTICAL from [PreferenceKeys], so the whole
 * settings surface reads ONE key store with no persisted pref wiped. A SharedPreferences key is a
 * functional interface identifier (not creative expression), so carrying the value forward verbatim
 * is migration-safe AND legally clean; the GPL lineage of the derived CODE stays credited in
 * LICENSE/NOTICE (GPL §5: replace the code, keep the notice) — only the carried-forward key strings
 * move, never the derived identity code, and they are NOT claimed as clean-room originals.
 * `PreferenceKeys` is retained transiently (its consumers repoint to `TortaeKeys.X`) and
 * is removed once no live ref remains; until then it keeps its Garmatin GPL notice.
 *
 * Every key STRING VALUE is byte-identical to the value it had in `PreferenceKeys` —
 * a persisted SharedPreferences key string is a functional interface identifier, so carrying the
 * value forward verbatim is both migration-safe (no user pref is wiped) and legally clean; only
 * the surrounding structure and comments are authored original.
 *
 * ★ DATAPATH-SAFE LAW (R3 SPEC §1): settings write the VALUE only and carry ZERO live-arm
 * side-effects. `ModulesStateLoop` is the SOLE datapath-promotion authority — never arm a
 * native seam from a settings write.
 */
object TortaeKeys {

    // ── CAKE/YeAH Engine (default SharedPreferences; read by MonokumaDnsEngineManager) ──
    const val DNS_ENGINE_ENABLED = "pref_engine_enabled"        // engine master, DEFAULT ON
    const val DNS_ENGINE_STANDALONE = "pref_engine_standalone"  // engine runs as its own module (no DNSCrypt)

    // Stage-1 native Rust resolver in the C/UDP-53 datapath (the torta_resolve intercept). Constant-pillar
    // VALUE switch, DEFAULT ON (Socio default-ON #85, 2026-06-20): PresetApplier force-writes it true and
    // the one-root switch defaults ON. ★ Writing this key has ZERO live-arm side-effects — the live datapath
    // promotion is decoupled to the C-side release guard (ModulesStateLoop.isNativeResolverArmed() + the
    // BuildConfig.DEBUG || isNativeResolverArmed() gate); the udp.c path fail-safes (r<=0 -> unchanged sendto),
    // so an un-built / un-armed pool stays byte-identical. ModulesStateLoop is the SOLE arm authority.
    const val RESOLVER_NATIVE_ENABLED = "pref_resolver_native"

    // SOVEREIGN DNSCRYPT REWIRE — the transport-selection switch for the live Rust resolver pool. DEFAULT ON
    // (the Socio sovereign-rewire vision, 2026-06-25): when ON + DNSCrypt RUNNING, the Rust pool is built with
    // the DNSCrypt v2 stamps (MODE 2 = the Rust transport answers encrypted queries DIRECTLY), making the Rust
    // transport the PRODUCTION DEFAULT. The Go libdnscrypt-proxy.so STAYS spawned as the loopback listener and
    // is the automatic runtime FALLBACK: the C bridge (udp.c:478-498) calls torta_resolve first; on r<=0
    // (Rust decline / miss / panic-firewall) it falls through to the unchanged sendto to the Go loopback —
    // per-query, zero C change. When OFF, the pool is built with the do53 loopback to Go (MODE 1 = the Go
    // binary answers, Rust is inert) — the explicit user safety valve to force Go-only. The runtime
    // fallback detector (ResolverRuntime.maybeFallbackToGo) can flip the live pool to MODE 1 automatically
    // when Rust's transport_miss+panics rate exceeds the threshold under load. Writing this key has ZERO
    // live-arm side-effects (DATAPATH-SAFE LAW §1): the pool is reconfigured on the next DNSCrypt RUNNING edge
    // (ResolverRuntime.onDnsCryptStarted), never mid-flight.
    const val RESOLVER_USE_RUST_DNSCRYPT = "pref_resolver_use_rust_dnscrypt"

    // THE WARDEN — native Rust firewall-verdict seam in the C tun datapath (the torta_firewall_verdict
    // bridge, the proven #85 resolver mirror). Constant-pillar VALUE switch, DEFAULT ON (W6 landed):
    // PresetApplier force-writes it true and a live pref_warden_native switch ships in the PROTECTION surface.
    // ★ Writing this key has ZERO live-arm side-effects. The residual safety is STRUCTURAL, not pref-write
    // avoidance: even when armed, the Rust global Warden singleton is unconfigured (None => ABSTAIN), so the
    // verdict seam is byte-identical until a policy rule-set is fed; the C g_warden_native_enabled flag is
    // governed by the same ModulesStateLoop release path, never by a settings write.
    const val WARDEN_NATIVE_ENABLED = "pref_warden_native"

    // 3-tier depth gate (GeekGate). GEEK (DNS_ENGINE_EXPERT) reveals the pillar on/off switches; NERD
    // (DNS_ENGINE_NERD) reveals the raw numeric dials in EngineSettingsFragment. NERD implies GEEK
    // (GeekGate.isNerd = nerd && expert). Both DEFAULT OFF.
    const val DNS_ENGINE_EXPERT = "pref_engine_expert"
    const val DNS_ENGINE_NERD = "pref_engine_nerd"

    const val DNS_ENGINE_PRESET = "pref_engine_preset"          // preset key: default|ping|bandwidth|upload_download
    // The EXPLICITLY-tapped Tortä quick-setup row (privacy|gaming|balanced), stored on a preset tap so the
    // picker highlights the chosen row directly instead of INFERRING it from (enginePreset, rotation) — the
    // inference collides once GAMING/BALANCED also rotate (constant-pillar G2). UI-only, no datapath. Empty ⇒
    // no named row marked (the honest "Custom / hand-tuned" state). Read by reflectActivePreset.
    const val DNS_ENGINE_PRESET_ACTIVE = "pref_engine_preset_active"
    const val DNS_ENGINE_CADENCE_MS = "pref_engine_cadence_ms"       // NERD: probe cycle period, ms
    const val DNS_ENGINE_MAX_WINDOW = "pref_engine_max_window"       // NERD: YeAH cwnd cap
    const val DNS_ENGINE_FREE_THRESH = "pref_engine_free_thresh"     // NERD: FREE multiplier × 1000 (1050 = 1.05)
    const val DNS_ENGINE_COMPETE_THRESH = "pref_engine_compete_thresh" // NERD: COMPETE multiplier × 1000 (1250 = 1.25)

    // #49 THE BEAST SETTINGS — the NEW direct-to-Rust plane for the OVERHAULED Yeah TCP/UDP Beast
    // (torta_core beast/*.rs + LIVE_BEAST, the nautilus-rs port). These are DISTINCT from the deprecated
    // #129 DNS_ENGINE_* line above (which fed the retired EngineConfig/MonokumaDnsEngine orchestration
    // where the profiles were INERT): the SETTINGS pane stages here + ResolverRuntime re-pushes them
    // straight onto the live Beast (TortaCore.beastSet*) on every datapath start. Profiles carry a -1
    // "never staged" sentinel (leave the compiled default); tunables carry 0 = "unset / don't-clobber".
    const val BEAST_YEAH_PROFILE = "pref_beast_yeah_profile"     // Yeah brain: 0 Legacy · 1 Canonical · 2 LineRate
    const val BEAST_CAKE_PROFILE = "pref_beast_cake_profile"     // Soft-cake queue: 0 Legacy-AQM · 1 CoBALT
    const val BEAST_PRESET = "pref_beast_preset"                 // goal preset: 0 Default · 1 FastPing · 2 Omega · 3 UpDown
    const val BEAST_CYCLE_MS = "pref_beast_cycle_ms"            // CoDel/probe cycle period, ms (staged)
    const val BEAST_MAX_WINDOW = "pref_beast_max_window"        // YeAH cwnd ceiling (2..64)
    const val BEAST_FREE_THRESH = "pref_beast_free_thresh"      // FREE ratio × 1000 (1050 = 1.05)
    const val BEAST_COMPETE_THRESH = "pref_beast_compete_thresh" // COMPETE ratio × 1000 (1250 = 1.25)

    // Per-upstream Governor + the self-healing Solver (CAKE/YeAH enrichment, Stage B+).
    // GOVERN (Expert, DEFAULT OFF) promotes the single YeAH/CAKE pair to a per-upstream governor map; when OFF
    // the engine is the byte-identical single-yeah/single-cake 6-probe loop and an untouched install never
    // builds the map. Landed in SHADOW first (configure is a no-op), so even ON it cannot throttle real DNS
    // until live Stage-C arming.
    const val DNS_ENGINE_GOVERN = "pref_engine_govern"          // Expert master, DEFAULT OFF
    const val DNS_ENGINE_QMAX_FRAC = "pref_engine_qmax_frac"    // NERD: YeAH Q-cap fraction × 100 (50 = 0.50)
    const val DNS_ENGINE_RHO = "pref_engine_rho"                // NERD: COBALT/CoDel rho window (default 16)

    // SOLVER — the noob-facing "auto-heal my connection" self-healer (DEFAULT ON, safe by design). On an
    // obstruction signal it races transport×resolver×relay off-pool, locks the winning binding (live commit
    // DEFERRED — shadow-rendered until GOVERN + Stage-C land) and caches it per network fingerprint. ANTI-THRASH
    // is load-bearing (hysteresis + dwell + cost-of-switching + cooldown + debounce): the pure state machine
    // cannot commit a marginal/transient swap, and with GOVERN OFF the live trigger source is absent so the
    // Solver runs SHADOW-only (= exactly today's datapath). The expert dials ride the SAME DNS_ENGINE_EXPERT gate.
    const val DNS_ENGINE_SOLVER = "pref_engine_solver"                          // noob "auto-heal", DEFAULT ON
    const val DNS_ENGINE_SOLVER_DWELL_MS = "pref_engine_solver_dwell_ms"         // NERD: min binding residency, ms (anti-thrash I2)
    const val DNS_ENGINE_SOLVER_COOLDOWN_MS = "pref_engine_solver_cooldown_ms"   // NERD: post-solve refractory window, ms (I4)
    const val DNS_ENGINE_SOLVER_TRIGGER_ENTER = "pref_engine_solver_trigger_enter" // NERD: obstruction enter threshold × 1000 (700 = 0.70) (I1)
    const val DNS_ENGINE_SOLVER_TRIGGER_EXIT = "pref_engine_solver_trigger_exit"   // NERD: obstruction exit threshold × 1000 (400 = 0.40) (I1 hysteresis low band)
    const val DNS_ENGINE_SOLVER_CONFIRM_SAMPLES = "pref_engine_solver_confirm_samples" // NERD: consecutive over-threshold ticks to trigger (default 3) (I5 debounce)
    const val DNS_ENGINE_SOLVER_SWITCH_MARGIN = "pref_engine_solver_switch_margin"     // NERD: cost-of-switching margin × 1000 (150 = 1.15× incumbent) (I3)
    const val DNS_ENGINE_SOLVER_CACHE_TTL_MS = "pref_engine_solver_cache_ttl_ms"       // NERD: fingerprint binding cache TTL, ms (I6 stickiness)

    // Resolver rotation (privacy). The noob master rotates the upstream resolver set on a cadence so no single
    // resolver sees a long-lived view of your queries. DEFAULT ON (v1 default-ON privacy pillar): a fresh install
    // rotates out of the box — the GEEK switch turns it off (USER FREEDOM). Read by RotationManager. When OFF,
    // RotationManager.start() is a no-op. Cadence/policy are EXPERT (behind DNS_ENGINE_EXPERT).
    const val RESOLVER_ROTATION_ENABLED = "pref_resolver_rotation"  // noob switch, DEFAULT ON (privacy pillar)
    // MINUTE-granular cadence (default 30 min diversity window). Stored as an int count of MINUTES; the consumer
    // converts minutes*60_000L → ms (RotationManager.readCadenceMs) and minutes*60L → secs for the Rust durable
    // cursor (rotation.rs cadence_secs). GEEK sets it via a preset ListPreference; NERD overrides the raw minutes
    // (EngineSettingsFragment, clamped MIN..MAX). A bad/absent value falls back to the consumer's 30-min default.
    // (Replaces the old hour-granular key — a fresh-fork pref, default-OFF rotation meant the old value was never
    // written, so no migration map.) ⚠ A GEEK ListPreference persists a String → the non-persistent bridge key
    // pref_torta_rotation_cadence_geek converts to this int via putInt; never make that bridge persistent.
    const val RESOLVER_ROTATION_CADENCE_MINUTES = "pref_resolver_rotation_cadence_minutes" // Expert, default 30 (min-granular)
    const val RESOLVER_ROTATION_POLICY = "pref_resolver_rotation_policy"    // Expert: trust|rtt|diversity (default diversity)

    // dnsmasq-completion — the local-DNS pillar toggles (read by resolver/mod.rs configure() as each feature
    // lands; surfaced + tapped-through by the Dnsmasq Dashboard card). NOOB pillars default the privacy-first
    // way; the raw geek knobs (cache_rr/filter_rr/proxy_dnssec/all_servers) are behind DNS_ENGINE_EXPERT.
    // local_records is a LIST/store (host-pin map), NOT a bool, so it has no on/off key here.
    const val DNSMASQ_CLOAK_ACTION = "pref_dnsmasq_cloak_action"  // noob 3-way: nxdomain|zerosink|customip (default nxdomain)
    const val DNSMASQ_BOGUS_PRIV = "pref_dnsmasq_bogus_priv"      // noob switch, DEFAULT ON (privacy: NXDOMAIN private PTRs)
    const val DNSMASQ_NEVER_FORWARD = "pref_dnsmasq_never_forward" // noob switch, DEFAULT ON (keep RFC6761/8375 names local)
    const val DNSMASQ_CACHE_RR = "pref_dnsmasq_cache_rr"          // Expert switch, DEFAULT ON (cache HTTPS/SVCB rrtypes)
    const val DNSMASQ_FILTER_RR = "pref_dnsmasq_filter_rr"        // Expert switch, DEFAULT ON (ANY-defang RFC8482; never strips A/AAAA)
    const val DNSMASQ_PROXY_DNSSEC = "pref_dnsmasq_proxy_dnssec"  // Expert switch, DEFAULT ON (AD-bit pass-through)
    const val DNSMASQ_ALL_SERVERS = "pref_dnsmasq_all_servers"    // Expert switch, DEFAULT ON (all-servers race vs strict-order)

    // MaskSolver Expert-toggle DURABILITY (#51) — these 6 knobs are live process-globals in torta_core
    // (pool.rs SOLVE_LADDER/QUERY_TIMEOUT_MS_OVERRIDE, cache.rs CACHE_CAP_INTENT/SERVE_STALE/TTL_FLOOR/TTL_CEILING)
    // that RESET to their compiled default on every engine (.so) restart. The MaskSolver SETTINGS pane's setters
    // now mirror the user's pick to these keys, and ResolverRuntime.applyDnsmasqTogglesFromPref re-pushes them on
    // the next configure — so an Expert pick survives a VPN-off / app-kill / reboot (the rotation-cadence law,
    // applied to the engine plane). Each default MATCHES the Rust compiled default so a fresh/untouched install is
    // byte-identical (solve-ladder OFF; the 5 ints 0 = engine default, only a user-armed >0 overrides on restore).
    const val RESOLVER_SOLVE_LADDER = "pref_resolver_solve_ladder"          // Expert switch, DEFAULT OFF (verdict-gated retry ladder)
    const val RESOLVER_CACHE_CAP = "pref_resolver_cache_cap"                // Expert int, 0 = the configured default cap
    const val RESOLVER_QUERY_TIMEOUT_MS = "pref_resolver_query_timeout_ms"  // Expert int, 0 = engine default per-query deadline
    const val RESOLVER_SERVE_STALE_SECS = "pref_resolver_serve_stale_secs"  // Expert int, 0 = OFF (RFC 8767 serve-stale window)
    const val RESOLVER_TTL_FLOOR_SECS = "pref_resolver_ttl_floor_secs"      // Expert int, 0 = no floor (min-cache-ttl)
    const val RESOLVER_TTL_CEILING_SECS = "pref_resolver_ttl_ceiling_secs"  // Expert int, 0 = the 24h default (max-cache-ttl)

    // Centauri remote signed-artifact channel (OPT-IN; DEFAULT OFF). An untouched install NEVER downloads/
    // installs a remote artifact: the manual/DNSCrypt compileFromFiles path stays the byte-identical default.
    // Behind an Expert toggle; read by CentauriArtifactManager.
    const val CENTAURI_REMOTE_ENABLED = "pref_centauri_remote_enabled" // master opt-in (default false)
    const val CENTAURI_REMOTE_URL = "pref_centauri_remote_url"         // base URL of the signed .tblk channel

    // Task #19 — SOURCE-LIST auto-update kill-switch. The resolver/relay/ODoH lists self-refresh in-file
    // (minisign-verified against the pinned dnscrypt.info key) so the rotation pool GROWS over time (that
    // pool spans 1200+ servers when all resolver/relay filters + IPv4/IPv6 + DNSCrypt/DoH/ODoH are on).
    // DEFAULT ON: fresh resolvers are the app's core purpose and match the dnscrypt-proxy `[sources]`
    // default. The slice-1 privacy concern is closed — the fetch resolves its CDN host THROUGH DNSCrypt and
    // opens TLS directly to that IP (SNI = host), failing closed if the resolver is not serving; it never
    // touches the system resolver. Read by SourceListUpdateManager.shouldAutoUpdate.
    const val SOURCE_LIST_AUTOUPDATE_ENABLED = "pref_source_list_autoupdate" // master, DEFAULT ON

    // Centauri Local Mirror — the in-app self-filling content-addressed CDN loopback server (CONSTANT pillar;
    // DEFAULT ON, Socio default-ON 2026-06-20). CentauriMirrorManager starts the loopback mirror (gated under the
    // Rust `mirror` cargo feature: the BASE .so has no mirror symbols, so the facade degrades to inert — never an
    // UnsatisfiedLinkError). SAFE-by-construction: loopback-only (127.0.0.1, no egress) + self-heal-not-block.
    // Force-written ON by PresetApplier. Reversible via its switch.
    const val CENTAURI_MIRROR_ENABLED = "pref_centauri_mirror_enabled" // constant pillar, DEFAULT ON
    // The Centauri SEED POLICY (SETTINGS · the seed-policy chip): 0 CatalogOnly (install + serve/rehydrate
    // lazily, NO proactive fetch batch) · 1 WarmUpBatch (also run the bounded TIER-B self-fill at arm — the
    // DEFAULT, preserving the pre-settings behavior). CentauriMirrorManager reads it at arm to gate step 5;
    // the Centauri ||| SETTINGS pane cycles + surfaces it (CentauriMirrorManager.SEED_POLICY_* codes).
    const val CENTAURI_SEED_POLICY = "pref_centauri_seed_policy" // 0 CatalogOnly · 1 WarmUpBatch (default)

    // Wireless Debug (no-root) self-elevation — protected state.
    const val WIRELESS_DEBUG_GRANTED = "wireless_debug_granted"
    const val WIRELESS_DEBUG_GRANTED_AT = "wireless_debug_granted_at"
    // No-Root Power channel. Wireless Debug is inherently Expert/Diagnostics-gated (geek-only, simple-UX): this
    // key gates the in-UI raw ADB command log + custom grant list + manual host:port. DEFAULT OFF — an untouched
    // install never reveals the geeky surface. The elevation flow itself does NOT depend on this key.
    const val WIRELESS_DEBUG_EXPERT = "pref_wireless_debug_expert"
    // Per-power verify-then-reapply persistence map (replaces the flat granted boolean for status). A JSON object
    // keyed by power id → {desired, lastVerified(epochMs), lastResult}, re-applied on boot for drift-prone powers.
    // When absent or unparseable the GrantEngine treats every power as un-applied (fail-closed, never fakes
    // "protected").
    const val WIRELESS_DEBUG_POWER_MAP = "wireless_debug_power_map"
    // #50 Wire Cake Inu SETTINGS — the three KOTLIN-owned durability prefs the typed InuState does NOT carry
    // (it holds pair/powers/expert/provider/elevation; these three are policy that lives outside the store).
    // The Inu ||| SETTINGS pane STAGES them here + reads them back through TortaPillarBridge.stagedInuConfig();
    // SharedPreferences IS the durable source (survives VPN-off / app-kill / reboot — the #51 durability law),
    // read on-demand by the boot receiver / notification / provider ordering (no live engine to push to yet).
    const val INU_BOOT_REAPPLY = "pref_inu_boot_reapply"     // LEGACY (#21): live flag moved to Rust InuState.bootReapply (hdr bit2); key survives only for the LegacyInuMigration one-shot absorb (read → fold → removed)
    const val INU_ALWAYS_ON = "pref_inu_always_on"           // the always-on foreground pairing notification
    const val INU_PROVIDER_PREF = "pref_inu_provider_pref"   // elevation-path preference: 0 AUTO · 1 SHIZUKU · 2 SELF-ADB

    // #93 — Custom-blocklist Expert screen (BlocklistSearchFragment). All ADDITIVE + Expert-gated, privacy-first:
    // the GitHub search is opt-in/surfaced/one-shot, the trust score is LOCAL (no network). An untouched install
    // never reaches the screen and never makes a network request from here.
    const val BLOCKLIST_SEARCH_DISCLOSED = "pref_blocklist_search_disclosed" // one-time GitHub-privacy disclosure flag
    const val BLOCKLIST_SEARCH_CACHE = "pref_blocklist_search_cache"          // 1h result cache: serialized JSON
    const val BLOCKLIST_SEARCH_CACHE_TS = "pref_blocklist_search_cache_ts"    // cache epoch-ms timestamp
    const val CUSTOM_BLOCKLIST_URLS = "pref_custom_blocklist_urls"            // user-added raw blocklist URLs (serialized set/JSON)

    // In-app education (#90a). TORTA_SHOW_TIPS gates the NON-BLOCKING "Did you know?" launch tip overlay
    // (default ON; a disable toggle is user-freedom). TORTA_TIP_INDEX is the rotating cursor into the tips array
    // so each launch surfaces a different tip. Pure UI: no datapath/arming, never gates use.
    const val TORTA_SHOW_TIPS = "pref_torta_show_tips"
    const val TORTA_TIP_INDEX = "pref_torta_tip_index"

    // Pillar 13 keep-alive: the NON-BLOCKING battery-optimization card "remind me later" snooze timestamp
    // (epoch ms). The card re-surfaces only after the keep-alive remind interval. Permanent dismiss reuses the
    // inherited DoNotShowIgnoreBatteryOptimizationDialog flag (one source of truth). Guide-not-gate: the app is
    // fully usable whether or not this is ever acted on.
    const val BATTERY_KEEPALIVE_REMIND_AT = "BatteryKeepAliveRemindAt"

    // ════════════════════════════════════════════════════════════════════════════════════════════
    // R3 settings-unify (de-InviZible) — CARRIED-FORWARD legacy keys. These key STRINGS originate in
    // the InviZible-DERIVED PreferenceKeys (the app shell, Fast/Common/DNSCrypt settings, firewall,
    // VPN, proxy). They are re-homed here BYTE-IDENTICAL so the unified settings surface keeps ONE
    // key store and NO persisted user pref is wiped. A SharedPreferences key is a functional
    // interface identifier (not creative expression), so carrying the value forward verbatim is
    // migration-safe AND legally clean; the GPL lineage of the derived CODE is credited in
    // LICENSE/NOTICE (GPL §5: replace the code, keep the notice). NOT claimed as clean-room
    // originals — only the surrounding structure is authored here. ★ DATAPATH-SAFE LAW still holds:
    // VALUE-only keys, zero live-arm side-effects.
    // ════════════════════════════════════════════════════════════════════════════════════════════

    // App shell / lifecycle / apps / firewall-state / remote-blocklist URLs
    const val WIFI_ACCESS_POINT_IS_ON = "APisON"
    const val USB_MODEM_IS_ON = "ModemIsON"
    const val DO_NOT_SHOW_IGNORE_BATTERY_OPTIMIZATION_DIALOG = "DoNotShowIgnoreBatteryOptimizationDialog"
    const val DO_NOT_SHOW_REQUEST_DATA_RESTRICTION_DIALOG = "DoNotShowRequestIgnoreDataRestrictionDialog"
    const val DNSCRYPT_READY_PREF = "DNSCrypt Ready"
    const val SAVED_DNSCRYPT_STATE_PREF = "savedDNSCryptState"
    const val CHILD_LOCK_PASSWORD = "passwd"
    const val ROOT_IS_AVAILABLE = "rootIsAvailable"
    const val OPERATION_MODE = "OPERATION_MODE"
    const val UNLOCK_APPS = "unlockApps"
    const val CLEARNET_APPS = "clearnetApps"
    const val APPS_DIRECT_UDP = "directUdpApps"
    const val APPS_BYPASS_VPN = "bypassVpnApps"
    const val IPS_TO_UNLOCK = "ipsToUnlock"
    const val IPS_FOR_CLEARNET = "ipsForClearNet"
    const val IPS_TO_UNLOCK_TETHER = "ipsToUnlockTether"
    const val IPS_FOR_CLEARNET_TETHER = "ipsForClearNetTether"
    const val TILES_LIMIT_DIALOG_NOT_SHOW = "tilesLimitDialogNotShow"
    const val ARP_SPOOFING_NOT_SUPPORTED = "arpSpoofingNotSupported"
    const val FIREWALL_WAS_STARTED = "FirewallWasStarted"
    const val FIREWALL_ENABLED = "FirewallEnabled"
    const val APPS_ALLOW_LAN_PREF = "appsAllowLan"
    const val APPS_ALLOW_WIFI_PREF = "appsAllowWifi"
    const val APPS_ALLOW_GSM_PREF = "appsAllowGsm"
    const val APPS_ALLOW_ROAMING = "appsAllowRoaming"
    const val APPS_ALLOW_VPN = "appsAllowVpn"
    const val APPS_NEWLY_INSTALLED = "appsNewlyInstalled"
    const val WIFI_ON_REQUESTED = "wifiOnRequested"
    const val GSM_ON_REQUESTED = "gsmOnRequested"
    const val MAIN_ACTIVITY_RECREATE = "refresh_main_activity"
    const val NOTIFICATIONS_REQUEST_BLOCKED = "notificationsAreBlocked"
    const val AGREEMENT_ACCEPTED = "Agreement"
    const val CRASH_REPORT = "CrashReport"
    const val GP_DATA = "gpData"
    const val GP_SIGNATURE = "gpSign"
    const val REMOTE_BLACKLIST_URL = "remote_blacklist_url"
    const val REMOTE_WHITELIST_URL = "remote_whitelist_url"
    const val REMOTE_IP_BLACKLIST_URL = "remote_ip_blacklist_url"
    const val REMOTE_FORWARDING_URL = "remote_forwarding_url"
    const val REMOTE_CLOAKING_URL = "remote_cloaking_url"

    // VPN
    const val VPN_SERVICE_ENABLED = "VPNServiceEnabled"

    // Fast Settings
    const val SITES_IPS_REFRESH_INTERVAL = "pref_fast_site_refresh_interval"
    const val CONNECTION_LOGS = "pref_fast_logs"
    const val BLOCK_HTTP = "pref_fast_block_http"
    const val BYPASS_LAN = "Allow LAN"
    const val AUTO_START_DELAY = "pref_fast_autostart_delay"
    const val PREVENT_DNS_LEAKS = "pref_fast_prevent_dns_leak"
    const val BLOCK_LAN_ON_FREE_WIFI = "pref_fast_block_lan_with_free_wifi"

    // Common Settings
    const val ARP_SPOOFING_DETECTION = "pref_common_arp_spoofing_detection"
    const val ARP_SPOOFING_BLOCK_INTERNET = "pref_common_arp_block_internet"
    const val ALWAYS_SHOW_HELP_MESSAGES = "pref_common_show_help"
    const val RUN_MODULES_WITH_ROOT = "swUseModulesRoot"
    const val FIX_TTL = "pref_common_fix_ttl"
    const val COMPATIBILITY_MODE = "swCompatibilityMode"
    const val DNS_REBIND_PROTECTION = "pref_common_dns_rebind_protection"

    /**
     * The CLIENT-DoH BOOTSTRAP SINKHOLE toggle. Denies the curated set of hostnames a browser uses
     * to bootstrap its OWN encrypted resolver, so it cannot hand DNS visibility to its provider and
     * blind every pillar after a single lookup. Default ON (see [ResolverRuntime]); the user can
     * turn it off if they deliberately want their browser's Secure DNS.
     */
    const val DNS_DOH_SINKHOLE = "pref_common_dns_doh_sinkhole"
    const val USE_PROXY = "swUseProxy"
    const val PROXY_ADDRESS = "ProxyServer"
    const val PROXY_PORT = "ProxyPort"
    const val PROXY_USER = "ProxyUserName"
    const val PROXY_PASS = "ProxyPass"
    const val MULTI_USER_SUPPORT = "pref_common_multi_user"
    const val FAST_NETWORK_SWITCHING = "pref_common_fast_network_switching"
    const val REFRESH_RULES = "swRefreshRules"
    const val KILL_SWITCH = "swKillSwitch"
    const val ALWAYS_ON_VPN = "always_on_vpn"
    const val USE_IPTABLES = "pref_common_use_iptables"
    const val WAIT_IPTABLES = "pref_common_wait_iptables"
    const val REMOTE_CONTROL = "pref_common_shell_control"

    // DNSCrypt Settings
    const val DNSCRYPT_SERVERS = "DNSCrypt Servers"
    const val DNSCRYPT_BLOCK_IPv6 = "block_ipv6"
    const val DNSCRYPT_LISTEN_PORT = "listen_port"
    const val IGNORE_SYSTEM_DNS = "ignore_system_dns"
    const val HTTP3_QUIC = "http3"
    const val DNSCRYPT_BOOTSTRAP_RESOLVERS = "bootstrap_resolvers"
    const val DNSCRYPT_NETPROBE_ADDRESS = "netprobe_address"
    const val DNSCRYPT_DNS64 = "dns64"
    const val DNSCRYPT_DNS64_PREFIX = "dns64_prefix"
    const val DNSCRYPT_OUTBOUND_PROXY = "Enable proxy"
    const val DNSCRYPT_OUTBOUND_PROXY_PORT = "proxy_port"
    const val DNSCRYPT_SERVERS_REFRESH_DELAY = "refresh_delay"
    const val DNSCRYPT_RELAYS_REFRESH_DELAY = "refresh_delay_relays"
    const val DNSCRYPT_RULES_REFRESH_DELAY = "refresh_delay_rules"
    const val DNSCRYPT_BINARY_CHECK_DELAY = "dnscrypt_binary_check_delay"
    const val DNSCRYPT_UPSTREAM_VERSION = "dnscrypt_upstream_version"
    const val DNSCRYPT_UPDATE_AVAILABLE = "dnscrypt_update_available"

    // Firewall Settings
    const val FIREWALL_NO_BLOCK_NEW_APP = "NewAppsInternetAllowed"
    const val FIREWALL_SHOWS_ALL_APPS = "FirewallShowsAllApps"

    // Logs
    const val SAVE_ROOT_LOGS = "swRootCommandsLog"

    // Proxifier
    const val PROXIFY_DNSCRYPT = "ProxifyDNSCrypt"
}
