# THE MONSTER, PERFECTED — CAKE+YeAH MonokumaDnsEngine Enhancement Plan

> Ultraplanned (4-agent workflow), grounded in the verified code + CAKE/YeAH literature. Staged, shadow-flagged,
> NEVER regresses DNS. Built next via max Ultracode + a refute-swarm Perfect Review + emulator proof per stage.

## 1 · The honest truth (verified, file-by-file)
The engine today is a **faithful, well-tested YeAH relay-selector with a CAKE-flavored façade**. `runCycle()` (every
`cycleMs`=5000) selectBestEndpoint (UDP-scan 3 endpoints, EWMA α=0.2, retarget pool) → enqueueBatch **exactly 6 probes**
(3 TCP+3 UDP, one per tin) → `cake.dispatch(cwnd)` strict-priority → fire parallel, TCP RTT→`yeah.apply`, emitMetrics.
**Because only 6 probes/cycle flow, the CAKE tins/AQM NEVER fire in steady-state and `cwnd>6` is INERT** — until real
query traffic fills the tins. That gap is exactly what P7 Wave 2 (the Rust resolver) exposes and what "Perfect" must close.
CAKE today = overflow/tail drop only (no CoDel sojourn, no BLUE, no DRR++, no fairness, no hashing; `endpointIdx` set but
never read). YeAH today = EWMA `baseRtt` (not a min), unconditional `cwnd/2` on loss, no `Q=(rtt−base)(cwnd/rtt)` estimator,
no fast/slow gating.

## 2 · Core reframe (the spine)
**CAKE = which queries go now/wait/shed (AQM + fairness). YeAH = how many per upstream (window/rate, Little's law
inflight=rate×RTT). Today conflated → separate into a two-loop controller where CAKE's AQM verdict GATES YeAH's growth.**
Resolutions: per-upstream `YeahController` (Map<upstreamId,UpstreamGovernor>) + set-associative buckets keyed `(endpointIdx,qname)`;
semaphore concurrency-cap = enforcement primitive, pacing `cwnd/(baseRtt/1000)` = derived metric; window-relative
`Q_MAX_FRAC` (Q>cwnd·frac) NOT absolute α=80 (DNS window is cwnd≤16..64).

## 3 · Enhanced CAKE/AQM (Kotlin, no native)
- **3.1 Real COBALT** per tin (add `enqueuedAtMs` to DnsProbeRequest): CoDel on `sojourn=now−enqueuedAtMs` (queue wait,
  not RTT): `target=5ms`, `interval=max(20ms,baseRtt)`; `dropNext += interval/√count`. + BLUE valve: timeout/fail
  `blueProb+=0.0025` (cap 0.25), decay on success. **Drop = SHED/deprioritize/SERVFAIL-fast, NEVER silent discard;
  CRITICAL tin floor-protected; probes droppable freely.**
- **3.2 DRR++** deficit fairness: per-flow `deficit` + `quantum≈1–2`; "++" = empty flow that just got a query goes on a
  **new-flows list served AHEAD** of old-flows RR → a fresh interactive lookup never waits behind a chatty flow (~99% of
  DNS is sparse one-shots → fast path, skips RR → also the overhead mitigation).
- **3.3 8-way set-associative hashing** `bucket=hash(endpointIdx,qname)%numSets` → per-upstream isolation for free
  (slow DoH3 backs up only its bucket) + kills cross-domain HOL-blocking.
- **3.4 DiffServ tins by WRR** (Interactive/Background/Bulk, shares ~[100,50,12]) not strict priority → no starvation
  either direction (a Bulk cert-fetch can't block foreground; chatty foreground can't starve a cert refresh).
- **3.5 free/compete redefined AQM-gated:** `free`= sojourn<target AND blueProb≈0 → YeAH may grow; `compete`= sojourn>target
  OR blueProb rising OR timeout → back off. Keep RTT multipliers (1.05/1.25) but gate them with the AQM verdict.

## 4 · Enhanced YeAH (per-upstream)
**HARD constraint: keep `YeahController()` no-arg byte-identical** (8 pinned YeahControllerTest transitions + adaptiveTimeoutMs
stay green). Real-YeAH brain behind `profile: YeahProfile` enum = LEGACY(default, exact current) / CANONICAL / LINERATE.
**The EWMA `baseRtt` field stays untouched**; add a SEPARATE `rttBaseFloor` (true-min, leaky-bucket `min(rtt, floor*1.02)`
→ re-learns a faster path in ~35 samples) used ONLY by the canonical Q math.
New state (CANONICAL): rttBaseFloor, rttMinSample, qPackets, renoCount, switchCount, fastMode, cwndCnt.
Params: PHI=8 (fast iff L=(rtt−base)/base<1/8), Q_MAX_FRAC=0.5 (→ Expert `DNS_ENGINE_QMAX_FRAC`, per-preset: FAST_PING 0.33,
OMEGA_BANDWIDTH 0.75), GAMMA=1.0, EPSILON_SHIFT=3 (cap shed cwnd/8), DELTA_SHIFT=3 (loss floor cwnd/8), RHO=16, ZETA=50, STCP_AI=8.
State machine: fastMode=(Q<cwnd·Q_MAX_FRAC)&&(L<1/PHI) → STCP scalable +1 every min(cwnd,STCP_AI); else if Q>cwnd·Q_MAX_FRAC →
**PRECAUTIONARY DECONGESTION** (shed min(Q/GAMMA, cwnd>>EPSILON_SHIFT) BEFORE any loss); else Reno additive → RECOVERY.
`onLossOrTimeout()` replaces blind cwnd/2: if renoCount>RHO (proven contention) full Reno halve (fair); else gentle floor
clamp(Q, cwnd>>DELTA_SHIFT, cwnd>>1) → an isolated UDP loss no longer collapses the window. The two upgrades that make it
"YeAH not Vegas-AIMD": precautionary decongestion + gentle-when-isolated/full-halve-only-under-contention.
**Per-upstream:** `UpstreamGovernor(endpoint){ yeah=YeahController(CANONICAL), pacer=Semaphore(cwnd), jitter=Welford,
score=blend(p95,loss,cwnd,jitter) }`; engine holds Map<upstreamId,UpstreamGovernor>; selectBestEndpoint → weighted spray +
small exploration (keeps every floor live); failover penalty per-governor (no shared-baseRtt poisoning). `score` = P8 trust feed.

## 5 · Integration / Wave 2 Rust seam (2 JNI calls/cycle, NEVER per-query)
`nativeResolverConfigure(json)` = {upstream→cwnd cap} + adaptiveTimeoutMs + pacing budget → resolver enforces
`inflight[upstream] ≤ cwnd[upstream]` via `Semaphore(cwnd)` (every real query acquire/release; overflow queues in CAKE
tins). `nativeResolverStats()` → fold REAL completed-query RTT→`yeah.apply`, timeout→`applyTimeoutPenalty`,
conn-error→`applyFailoverPenalty`. **Strictly additive: null stats ⇒ today's 6-probe path unchanged** (a build without
resolver JNI behaves exactly as today). Probes degrade to keepalive/cold-start under real traffic (battery win). Adaptive
cadence (traffic→5–10s stats tick; idle→15–30s + cold-start probe), ride ModulesService's existing WakeLocksManager (NO 2nd
wakelock), best-effort under Doze. `stopEngine` MUST publish "release all caps" (no stale semaphore throttling DNS).
**NOTE: Wave 2b already shipped `nativeResolverConfigure/Resolve/Stats/Shutdown` + façades — the seam is half-wired.**

## 6 · Dashboard (every claim verifiable) — additive to DnsEngineMetrics
`upstreams: List<UpstreamMetric{name,protocol,cwnd,inflight,baseRttMs,jitterMs,mode,sent,ok,fail,timeout,qps}}` +
globals `realQps`, `inflightTotal/cwndTotal`, `pacingRateQps=cwnd/(baseRtt/1000)`, `probeFallbackActive`,
CAKE `sojournP50/P95Ms, blueProb, sparseFlowHits, perTinDispatched[3], bucketsOccupied, wayCollisions, cobaltDropped,
drrSparseServed`, blocklist observed/blocked, shadow `governedQps` vs `wouldHaveSentQps`. Ticker: `YEAH cwnd=8 rtt=14 qps=42 doh3:6 doq:2 ok=99% aqm=0 sojP95=4ms`.

## 7 · Staged rollout (flag `DNS_ENGINE_GOVERN` default false; every stage = emulator proof + tests green)
- **Stage A — internals behind profiles (no traffic change):** land §3 in CakeScheduler + §4 in YeahController behind
  CANONICAL/LINERATE; engine runs LEGACY in prod. Migrate the pinned CakeScheduler depth-4 drop test to COBALT; add
  CANONICAL/COBALT unit tests. Verify: all tests green; emulator boots/resolves; engine logs unchanged. **← BUILD FIRST.**
- **Stage B — Shadow (default ON, zero risk):** per-upstream governors + real Q run, configure is a no-op, engine only
  reads stats + renders new dashboard. DNS 100% unchanged. Verify: `tc netem` latency-step → precautionary decongestion
  fires in SHADOW numbers before any loss; success rate identical.
- **Stage C — Flagged enforcement (Expert opt-in):** flip GOVERN=true → resolver enforces inflight≤cwnd. Guardrails:
  hard floor cwnd≥MIN_WINDOW; safety-valve auto-demote to shadow+unbounded if success<95%/window. Verify head-to-head
  LEGACY vs CANONICAL: netem delay→sheds cwnd/8 w/o timeout; netem 5% isolated loss→renoCount<ρ→gentle (no collapse,
  the headline win); competing iperf3→renoCount>16→full halve (fair); relay flap→dead cwnd→1, other's baseRtt untouched.
- **Stage D — Default ON** after field validation; keep safety valve + kill switch (`DNS_ENGINE_ENABLED`).
- **Stage E — the SOLVER reflex (FlareSolverr's PRINCIPLE, pure networking, ZERO browser).** Built ON per-upstream
  governors. On obstruction (sojourn/blueProb spike, score collapse, throttle/captive-portal signature) escalate to an
  ACTIVE exploration: race `transport × resolver × relay` (DoH/DoH3/DoQ/DNSCrypt × pool × relays), measure, LOCK the
  optimal binding + tuned cwnd/CAKE params, CACHE the solution per network fingerprint (SSID/gateway → instant reuse),
  re-solve on change. Composition: YeAH/CAKE=steady-state · Solver=obstruction+discovery · P10=diversity. **The refute-swarm's
  prime target here: thrashing** (hysteresis/dwell-time/cost-of-switching — a self-healer that flaps is a new bug). NO Cloudflare/Chromium/WebView ever.

## 8 · Risks → mitigations
Pinned-test regression → LEGACY default + separate rttBaseFloor. Real query dropped → shed not discard + CRITICAL floor +
<95% safety valve. Stale floor → leaky ×1.02 re-learn. JNI chatter → 2 calls/cycle batched. Battery → adaptive cadence +
existing wakelock. DRR++/COBALT overhead → sparse fast-path 99%. Stale semaphore after stop → release-all-caps. Wave 2
not shipped → null-stats fallback to probe path (Stages A–B deliver value before the resolver exists). Solver thrash →
hysteresis + dwell-time + cost-of-switching (refute-swarm proves no-flap on emulator).

## Files that matter
dns_engine/core/{CakeScheduler.kt(§3), DnsProbeRequest.kt(enqueuedAtMs + endpointIdx key), YeahController.kt(§4 profile/Q/rttBaseFloor/onLossOrTimeout), YeahMode.kt} ·
dns_engine/{MonokumaDnsEngine.kt(UpstreamGovernor map, endCycle, stats fold), MonokumaDnsEngineManager.kt(configure-on-start/release-on-stop, GOVERN read), EngineConfig.kt(qMaxFrac/rho/profile/codelTargetMs/tinWeights/quantum/setAssocWays/pacingMode + presets)} ·
dns_engine/metrics/DnsEngineMetrics.kt(perUpstream + globals) · dns_engine/socket/ConnectionPool.kt(generalize pendingQueries/resize) ·
rust/TortaCore.kt(nativeResolverConfigure/Stats — DONE in 2b) · rust/BlocklistRuntime.kt(surface observed/blocked) ·
dns_engine/dashboard/DnsEngineDashboardFragment.kt(per-upstream rows + ticker) · utils/preferences/PreferenceKeys.java(DNS_ENGINE_GOVERN/QMAX_FRAC/RHO) ·
test/.../core/{YeahControllerTest, CakeSchedulerTest}(LEGACY keeps pinned green; migrate depth-4 drop to COBALT; add CANONICAL/COBALT tests).

**Essence:** keep LEGACY byte-identical + resolver-absent path unchanged; behind default-OFF `DNS_ENGINE_GOVERN`, give CAKE
real COBALT+DRR++ flow-isolated WRR tins and YeAH its real Q-based fast/slow brain, promote both per-upstream, wire the
2-call/cycle JNI seam where each upstream's cwnd = the concurrency semaphore on Wave 2's real queries; then the Solver reflex
on top — staged shadow→flagged→default with emulator proof at every step.
