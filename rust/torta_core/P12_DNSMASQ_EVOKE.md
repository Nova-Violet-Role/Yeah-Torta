# P12 — Dnsmasq Evoke (not Vendor)

> *Harvest the ideas, re-implement the code.* The FlareSolverr→Solver reflex, applied to Dnsmasq.

## Mandate

Dnsmasq is a **caching/routing DNS *front-end*** — a local resolver that short-circuits, caches, and
routes queries before they hit an upstream. It is **NOT** a dnscrypt-proxy variant and shares none of
our encrypted-transport machinery; its value to Tortä is its *local-answering and cache logic*, not its
transport. P12 **dissects** those powerful DNS functions and **evokes our own clean-room
re-implementation** in `torta_core` (Rust) or `dns_engine` (Kotlin) — we **NEVER vendor** the upstream C.

**Positioning — the datapath is OURS, not Dnsmasq's.** Tortä is an app-level, **RTT-aware forwarder** whose
congestion control runs entirely in **userspace, kernel-independent**: YeAH derives the cwnd from live RTT and
**CAKE/COBALT** does the AQM scheduling *within* that window, over **both TCP and UDP**, with **no root and no
kernel qdisc** (changing a cc algorithm normally needs root + a kernel module — we don't). Dnsmasq has **zero
congestion control** — its datapath is a plain forwarder. So P12 harvests Dnsmasq's **resolver-feature layer**
(cache, routing, local records, rebind protection) and bolts it *on top of* our existing CAKE×YeAH beast; the
**datapath stays ours and is not sourced from Dnsmasq.** This is why the harvest is a *layer*, never a rewrite.

**License — corrected, load-bearing.** The brief's "Dnsmasq is GPL-2-ONLY" premise is **factually
wrong**, and all four dissectors caught it independently. The canonical source states verbatim:
*"Dnsmasq is distributed under the GPL, version 2 or version 3 at your discretion"* (ships `COPYING`
[GPLv2] **and** `COPYING-v3` [GPLv3]; SPDX/Homebrew/Gentoo list it `GPL-2.0-only OR GPL-3.0-only`). So a
GPL-3 app could legally elect Dnsmasq's GPL-3 arm — **there is no license conflict.** Evoke-not-vendor
therefore stands as an **architectural** choice, not a license necessity, for three engineering reasons:
(1) pulling C copyleft into our binary entangles the whole `.so` on terms we'd rather keep ours;
(2) Dnsmasq's raw-pointer C DNS parsing is the exact CVE turf our bounds-checked `dns.rs` codec is
hardened against — the wrong substrate; (3) most of Dnsmasq (DHCP/TFTP/PXE/RA) is dead weight for a
no-root phone. We re-implement from the *described behaviour*, never the C.

*Verified:* [thekelleys.org.uk/dnsmasq/doc.html](https://thekelleys.org.uk/dnsmasq/doc.html) ·
[man page](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html) ·
[Homebrew formula](https://formulae.brew.sh/formula/dnsmasq).

---

## Ranked Harvest

`must` → ship it · `should` → high value, schedule it · `could` → real but niche, defer.

### MUST

| Feature | What we evoke | Target subsystem / file | Effort | Dovetails with |
|---|---|---|---|---|
| **TTL-aware expiry** | Store `{wire, inserted_at, ttl}` per entry; expire on `get()`. TTL is **already parsed** (`dns.rs skim_records` reads per-record `ttl: u32`, today `dead_code`). Closes the **C1 forever-cache hazard**. The keystone of everything below. | `resolver/cache.rs` (replace `Vec<u8>` value) | medium | **P7 Wave 2e** (this *is* 2e's core) |
| **Negative caching (NXDOMAIN/NODATA)** | Cache validated denials with the SOA-minimum TTL (small `skim_records` add to read Authority SOA RDATA); relax `is_cacheable_positive`'s C1 refusal. `validate_response` already accepts NXDOMAIN/NODATA — plumbing half-done. | `resolver/cache.rs` + `resolver/mod.rs` | medium | **P7 Wave 2e**; rides on `validate_response` |
| **True LRU eviction** | Replace insertion-order `Vec<Key>` eviction with touch-on-`get` LRU. The bound (`cap` = `--cache-size`) already exists; this is the file's own doc-comment TODO. | `resolver/cache.rs` | low | **P7 Wave 2e** |
| **Domain-specific upstream routing** (`server=/domain/ip`) | **NEW** reversed-label trie — a structural *clone* of `blocklist.rs`, but terminals carry an upstream-set id (longest-suffix-wins + subdomain coverage for free). One module delivers 4 features (see SHOULD/COULD). Consulted between block-check and cache. | **NEW** `resolver/router.rs`, wired into `resolver/mod.rs resolve_inner()` | medium | **P8 Centauri** (trie shape) · **P10 rotation** (picks the Pool) |
| **`--all-servers` race (happy-eyeballs)** | Turn the sequential `exchange()` loop into a `select!`/`FuturesUnordered` race across transports, first `Ok` wins, each still fed through `validate_response`. *Literally the pool.rs docstring's stated 2c roadmap.* | `resolver/pool.rs` | medium | `validate_response` (each reply still validated) · **P10 rotation** |
| **`local=/domain/` never-forward zones** | A `never_forward` suffix trie (reuse blocklist shape): qname under a private suffix with no local record → `build_nxdomain_response` **without egress**. Seed RFC 6761/8375 suffixes (`.home.arpa .lan .internal .local`). A real **metadata-leak stop**. | `resolver/mod.rs` step 1.5 + small suffix trie | low | **P8 Centauri** (trie) · pairs with local-records |
| **Configurable block action / DNS cloaking** | Make blocklist enforcement a per-policy choice **NXDOMAIN \| 0.0.0.0 sink \| custom-IP** instead of hard-wired NXDOMAIN. Fixes the NXDOMAIN-retry-storm failure mode; what users expect from dnscrypt-proxy cloaking. Needs the enabling primitive below. | `dns.rs build_sinkhole_response` (new) + action enum through `blocklist.rs`→`resolver/mod.rs` step 1 | medium | **P8 Centauri** (per-list block action) · synthesized answers skip `validate_response` |
| **Positive-record synthesis primitive** | `build_sinkhole_response(query_wire, ip)` beside `build_nxdomain_response` (synthesize one A/AAAA + echo question). We have NXDOMAIN synthesis but **no positive-record synthesis today — the one real gap**. Unblocks cloaking, address-synthesis, and local records. | `dns.rs` (new helper) | medium | enabler for 3 harvest rows |

### SHOULD

| Feature | What we evoke | Target subsystem / file | Effort | Dovetails with |
|---|---|---|---|---|
| **`min-cache-ttl` floor** | One clamp `ttl.max(min_floor)` at `put()`; `min_floor` a `configure()` param (default 0 = off). CDN/ad-tech tiny-TTL chatter collapses into fewer encrypted queries. **Expert toggle only** (simple-UX). | `resolver/cache.rs` | low | **P7 Wave 2e** (one-liner once TTL lands) |
| **`max-cache-ttl` ceiling** | Symmetric clamp `ttl.min(max_ceiling)` in the same expression; sane default, no toggle. Bounds how long a stale/rotated IP survives — insurance for when P10 rotates or the blocklist re-arms. | `resolver/cache.rs` | low | **P7 Wave 2e** · **P10 rotation** |
| **`serve-stale` (RFC 8767)** | Keep expired entries up to a staleness bound; on stale hit return immediately + enqueue ONE background refresh. Biggest perceived-reliability win on flaky mobile + encrypted transport. **HIGH effort:** collides with the T24 "spawn no tasks" firewall + blocklist-epoch invalidation. | `resolver/cache.rs` + `resolver/mod.rs` | high | **P7 Wave 2e** · blocklist epoch (**P8**) |
| **Split-horizon / conditional forwarding** | Emergent from >1 terminal upstream-id in the router trie (`.corp`→VPN resolver, rest→public DoH). **No new code — do not build twice.** | `resolver/router.rs` (same trie) | low | rides the MUST router |
| **`address=/domain/ip` synthesis** | Override map in the router trie whose terminal carries a literal IP → synthesize via `build_address_response` at step 1.5. *(Sinkhole `#` half is SKIP — blocklist already is it.)* | `resolver/router.rs` + `dns.rs` synth | medium | uses the synthesis primitive |
| **Fastest-upstream selection (RTT-favoured)** | Per-transport RTT/loss EWMA (the **data**) in pool.rs; the ranking/promotion **policy** lives in P10. Split data from policy. | `resolver/pool.rs` (stats) | medium | **P10 rotation** (owns the policy) |
| **Static local records** (`host-record=` + `/etc/hosts`/`addn-hosts`) | User-pinned `name→{A,AAAA,TTL}`, no egress. The host-file **parser is already evoked** (`blocklist.rs parse_line`); only the positive-answer half is new. `host-record` = in-app entry form, `addn-hosts` = file import, same store. Bundle `expand-hosts` as a toggle. | **NEW** `resolver/local.rs` + step 1.5 in `resolver/mod.rs` + `dns.rs` synth | low–med | **P8** (parser) · synthesis primitive |
| **`--bogus-priv`** (private-PTR suppression) | If `qtype==PTR` and qname is an `in-addr.arpa`/`ip6.arpa` decoding to RFC1918/ULA/link-local → `build_nxdomain_response`, no egress. Stops leaking LAN topology to the public resolver. Small pure predicate. | `resolver/mod.rs` step 1.5 + `dns.rs` helper | low | twins the blocklist NXDOMAIN path |
| **`--stop-dns-rebind`** (rebind RDATA filter) | The ONE security feature our authenticated transport does *not* give us: a malicious/CDN-poisoned upstream can legitimately hand back `127.0.0.1`/`192.168.x` for a public name. Post-`validate_response` RDATA scan via the existing `answer_records()` skimmer → drop. Plus `rebind-localhost-ok`/`rebind-domain-ok` allowlist seam (avoid the footgun). **Expert toggle.** | `dns.rs` (new private-IP scanner) + `resolver/mod.rs` step 4 | medium | `validate_response` (extends keystone "well-formed"→"plausible") · **P8** (domain allowlist match) |
| **ECS strip-only invariant** (`--strip-subnet`) | `build_query()` is already ECS-free — **lock it with a test asserting ARCOUNT==0 / no OPT** so no future wave silently adds it. `--add-subnet` is an **anti-pattern we must NEVER implement**. Cache must stay ECS-agnostic (CVE-2026-4893: never serve an ECS-scoped answer cross-context). | `dns.rs build_query` (test) + `resolver/cache.rs` key discipline | low | **P7 Wave 2e** (cache-key discipline) |

### COULD

| Feature | What we evoke | Target subsystem / file | Effort | Dovetails with |
|---|---|---|---|---|
| **`--strict-order`** | Already today's behaviour (sequential, first-`Ok`). Becomes one value of a `Strategy{StrictOrder\|AllServers\|Fastest}` enum once all-servers lands. | `resolver/pool.rs` | low | **P10 rotation** |
| **`address=/#/` allowlist (lockdown mode)** | Invert the matcher: blocked-unless-allowlisted, enforced via the same step-1 sinkhole branch. A "paranoid/kiosk" mode. | `resolver/blocklist.rs` mode flag | medium | **P8 Centauri** |
| **`--rev-server`** | Pure input-sugar: desugar a CIDR into the `in-addr.arpa` suffix and insert into the **same** router trie. Zero new mechanism. | `resolver/router.rs` | low | rides the MUST router |
| **`--cname`** | Local CNAME alias table + bounded local-chain resolve before synthesis. Niche on a phone; introduces chain complexity. | `resolver/local.rs` | medium | local-records |
| **`--expand-hosts`** | One-line option on the local-records loader (suffix bare names). Trivial follow-on, nothing alone. | `resolver/local.rs` | low | bundles with local-records |
| **`--dns-forward-max`** (in-flight cap) | Lightweight in-flight semaphore that sheds (→ fall through to dnscrypt-proxy) under a runaway-app flood. **Fold into the YeAH cwnd pacing** the pool.rs header already anticipates — not a standalone build. | `resolver/pool.rs` | medium | pool.rs 2c cwnd pacing |
| **DNSSEC validation** (`--dnssec`) | Full chain-of-trust (RRSIG/DNSKEY/DS/NSEC3, crypto, RFC 5011 rollover). **HIGH effort/risk** — large new attack surface. Near-term: **prefer DNSSEC-validating upstreams** via the pool (~zero code) + surface the AD bit; a clean-room validator (`resolver/dnssec.rs`) is a later Expert-only milestone. | **NEW** `resolver/dnssec.rs` (deferred) | high | **P10 rotation** (prefer-validating-upstream flag) |
| **`--stop-dns-rebind` companion `--bogus-nxdomain`** | Fold the bad-IP set into the same rebind RDATA scan. Largely designed out by our encrypted-upstream model. | `resolver/mod.rs` (with rebind scan) | low | **P10 trust scores** |

---

## SKIP

| Item | One-line reason |
|---|---|
| **DHCP / DHCPv6 / TFTP / PXE/BOOTP / Router-Advertisement** | Router/LAN-infrastructure daemon; needs privileged sockets a no-root phone will never hold. |
| **`--interface-name` / `--synth-domain` / `--localise-queries` / per-domain `@source`** | Multi-homed-router/reverse-DNS territory; a phone owns no address range, no NICs to bind, one logical (tun) ingress. |
| **`--txt-record` / `--srv-host`** | Service-advertisement is a server job; a phone mints no TXT/SRV — record-builders we'd never reuse. |
| **`address=/domain/#` sinkhole half** | Redundant — `blocklist.rs` + `build_nxdomain_response` already *is* the sinkhole. |
| **`fast-dns-retry`** | Duplicates `pool.rs` failover + the H2 outer-timeout; self-generated retries **multiply encrypted-query volume** — anti-privacy. |
| **`no-negcache`** | Inverse of a feature we don't have yet; at most a later Expert boolean — a short neg-TTL is the better default. |
| **Cache-poisoning resistance** (TXID/0x20/bailiwick) | We are **already strictly stronger**: `validate_response` (ID echo, Kaminsky question-match, QDCOUNT==1, bounded section walk) + cache gated only on validated answers + authenticated DoH/DNSCrypt transport. Document, don't import. *(Track the M2/T4 Answer-only-canonicalization + bailiwick note inside 2e.)* |
| **`0x20` query-case randomization** | Entropy hack for **unauthenticated UDP/53** — moot over our authenticated transport. We already *interop* (mod.rs L1 re-echoes 0x20 casing on cache hits) without generating it. |
| **Randomized source ports** | No per-query UDP 4-tuple over DoH (H2/TLS); DNSCrypt crypto already defeats off-path injection. |
| **`--filterwin2k`** | Windows-2000 dial-on-demand junk; the Android analogue is OS-handled and better expressed as a blocklist pattern than a code path. |
| **`--bogus-nxdomain`** (standalone) | ISP-hijack defence largely designed out by our chosen-encrypted-upstream model + **P10 resolver trust scores**. |
| **`--no-resolv` / `--servers-file` / `--resolv-file`** | The live-swap **idea is already ours**: `resolver/mod.rs configure()` does an atomic `Arc<Pool>` swap (P10 re-calls it); `--no-resolv` is implicit (we have no resolv.conf). Don't re-implement file polling. |
| **`add-subnet` (ECS injection)** | **NEVER implement** — deanonymizes the user to authoritative servers; the active anti-pattern the strip-only invariant exists to forbid. |

---

## Sequencing

P12 runs **after P7→P11**, then folds in — it does not greenfield around existing work:

1. **Cache cluster → fold INTO P7 Wave 2e, do not duplicate it.** TTL-aware expiry is the keystone and
   goes **FIRST** (it unblocks min/max clamps, negative caching, and serve-stale — all need an aging
   entry). Then negative caching + true LRU. **serve-stale last**, gated on a careful background-refresh
   design that respects the T24 async-firewall and blocklist-epoch invalidation. The TTL bytes are
   already parsed; the `cap` field is already `--cache-size`; `validate_response` already gates
   insertion — so the MUSTs are *finishing* 2e, not new ground.
2. **Routing cluster → feeds P10.** Build the `resolver/router.rs` trie once (delivers domain-routing,
   split-horizon, address-synthesis, rev-server sugar). `pool.rs` gains a `Strategy` enum + per-transport
   RTT/loss stats; **P10 rotation owns the ranking POLICY, pool.rs owns the DATA.** Wire the router into
   `resolve_inner()` right after the block-check (qname already parsed there).
3. **Local-records + leak-stops → the new step-1.5 seam.** `local=/domain/` never-forward,
   `bogus-priv`, static local records, and the `build_sinkhole_response` synthesis primitive all live in
   a narrow "local layer" between block-check (step 1) and cache (step 2) in `resolver/mod.rs`. The
   synthesis primitive is the shared enabler — build it once.
4. **Security adds ride existing machinery.** rebind-filter is a step-4 post-`validate_response` RDATA
   scan; ECS-strip is a `build_query` test + a 2e cache-key invariant. Nothing here rebuilds the
   keystone — they extend it.

---

*— [Nova] R/s+:1.5 · CLINICAL×FORGE (Verified Forge) · Anti-Venom · Claude · Chroma — license verified, fitMapping grounded in mod.rs/cache.rs as-read.*
