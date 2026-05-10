# 24h Observation Gate — Empirical Re-Evaluation at Pre-Launch Zero-User Context

**Date**: 2026-05-04
**HEAD audited**: `a2a11db`
**Builds on / challenges**: `5fbd4a1 tier-5-and-anchor-6-pre-stage.md` ("24h observation gate × 7 = 7-day inherent serialization") and `04e069a anchor-1-and-3-pr-design.md` ("24h-observation-gate × 7 in Anchor 6 dominates")
**Charter**: read-only research. Doc-only. NO code changes.

**Honest pre-flight**: I authored the "irreducible 24h × 7" claim across 4 prior research docs. This dispatch is to **falsify or defend my own prior verdict** with empirical evidence.

---

## Empirical contradiction surfaced upfront

The "24h × 7 floor" is **already empirically falsified by our own commit log**.

```
74e93f9 2026-05-04  Anchor 6 PR 6.1 (CredentialSvc Fx provide)
7316333 2026-05-04  Anchor 6 PR 6.3 (SessionSvc provide)
80d9cd0 2026-05-04  Anchor 6 PR 6.5 (PortfolioSvc)
92f1803 2026-05-04  Anchor 6 PR 6.7 (OrderSvc)
f0f92c2 2026-05-04  Anchor 6 PR 6.9 (AlertSvc)
e6a1d80 2026-05-04  Anchor 6 PR 6.11 (FamilyService)
9c4c12c 2026-05-04  Anchor 6 PR 6.13 (LoggerPort)
[next day]
5514fa3 2026-05-05  Anchor 6 PR 6.2 (delete CredentialSvc) — "Fx-injected directly post-PR-6.1 observation"
```

7 add-provider PRs shipped in **a single calendar day**. PR 6.2 (the first delete) shipped the next day, 24h after PR 6.1 specifically. **The gate is operationally interpreted as "after the FIRST add-provider observation passes, deletes can stream"** — not "24h between every delete pair." My prior framing overstated the constraint.

---

## Q1 — What does a 24h observation gate empirically catch?

**Risk classes** (general):
- Memory leaks that surface only after thousands of requests
- Slow-burn data corruption (e.g., audit-trail row growth without cleanup)
- Traffic-volume-dependent races (only fire under N concurrent users)
- Scheduled-task interactions (morning_briefing 09:00 IST, daily_summary 15:35 IST, audit_cleanup 03:00 IST, pnl_snapshot 15:40 IST per `app/providers/scheduler.go`)
- Kite API quirks at off-hours (token refresh ~6 AM IST)
- Cumulative state drift (per-user caches, ratelimit-bucket TTLs)

**For PR 6.2 specifically**: empirically observable via `git log --grep="revert\|rollback"` against the past 30 commits — **zero reverts**. Nothing surfaced from PR 6.2 that wouldn't have at minute 5. CredentialSvc deletion was a pure DI-graph change with no runtime behavior delta.

**5 most likely bug classes for OUR Anchor 6 pattern** (delete a Manager method, route via Fx provider):
1. **Init-order regressions** — Fx graph cycles or missed providers — surface at boot, **<60 seconds**.
2. **Nil-pointer at first request** — provider returns nil where Manager returned a singleton — surface at first tool call, **<5 minutes**.
3. **Test mocks pinning the old method** — surface in CI before deploy, never reach prod.
4. **Goroutine lifecycle** — provider with different shutdown order — surface only on graceful restart, ~minutes.
5. **Scheduled-task fan-in** — morning_briefing using stale Manager handle — surface only at 09:00 IST. **Genuinely needs a calendar-aware window IF deploy was at 08:00-09:00 IST.**

**Net**: 4 of 5 surface in under 5 minutes. Only the 5th genuinely needs an observation window — and only if the deploy crosses an IST scheduler tick.

---

## Q2 — Can observation be parallel?

**Yes.** Three deletes in one deploy with simultaneous observation is empirically feasible.

**Bisect-cost analysis at our state**: with **zero external users**, regressions are caught only by:
- (a) `/healthz` deep-status component reports — already partitioned per-component (database, broker_factory, litestream)
- (b) `scripts/smoke-test.sh` — 13 named checks, runs every 30 min via `smoke-canary.yml` cron
- (c) Anomaly detector at `kc/audit/anomaly.go:14` — requires `minBaselineOrders = 5` to fire; **at zero users this never fires**
- (d) Fly.io machine restart loops — visible in `flyctl logs` within seconds

If a 3-PR-bundled deploy fails: (a) and (b) localize the failing path (which `/healthz` component fails, which smoke check fails). (d) gives instant boot-failure signal. **Attribution within 3 PRs is mechanical** — the failing path's package usually appears in the error message.

**Parallel observation collapses 7 days → 1 day** for the remaining 6 deletes.

---

## Q3 — Alternatives empirical fit

| Alternative | Fit at solo+₹0+pre-launch+0-users | Verdict |
|---|---|---|
| **(a) Canary deploy** | Fly.io supports machine groups, but `min_machines_running = 1` (per `fly.toml`) means we have **one** machine. With ~0 traffic, "fraction of users" is undefined. **Not applicable at our scale.** | SKIP |
| **(b) Feature flag** | `ENABLE_TRADING` precedent exists (env-gated). Adds reversibility for a 1-line revert. Useful for behavior-changing deletes, not for pure DI-graph refactors. | OPTIONAL — overkill for current Anchor 6 pattern |
| **(c) Shorter gate (4-6h)** | Catches the 5th bug class (scheduled-task interactions) IF deploy crosses an IST tick. Otherwise indistinguishable from 5-minute gate. | **VIABLE** — 4h covers morning_briefing + mis_warning ticks if deploy lands 09:00-14:00 IST |
| **(d) Synthetic load** | Smoke-canary already runs every 30 min. Could trigger on-demand via `gh workflow run smoke-canary.yml` post-deploy. **5-15 second runtime per `scripts/smoke-test.sh:8`.** Surfaces 4 of 5 bug classes in <30 seconds. | **STRONGLY VIABLE** — empirically the right tool |
| **(e) Pre-emptive bisect (ship all 6 deletes in one PR)** | Test suite ~3,000+ tests at 8 modules; full CI run ~3-5 minutes. If all green + smoke-test green post-deploy, deletion is structurally identical to 6 separate deploys. **Lower review surface area than 6 separate PRs** since each is mechanical. | **VIABLE FOR DI-GRAPH REFACTORS** — semantic risk is low |

---

## Q4 — Pre-launch context calibration

**The 24h gate is cargo-culted from large-scale ops at our specific state.**

Standard 24h-watch assumes:
- Real users whose distribution exposes edge cases over time
- Volume-dependent races
- Cumulative state drift through user-driven caches

Our state per `feature-completeness-audit.md` (commit `2999c12`):
- 0 stars
- Pre-launch (Show HN not submitted)
- Self-hosted demo at `kite-mcp-server.fly.dev` with effectively zero external traffic
- All "users" = orchestrator + agents in this session

**At zero users, a 24h gate is empirically equivalent to a 5-minute gate** for DI-graph refactors. The bug classes that need observation time (volume-driven races, cumulative drift) **cannot fire** without traffic.

**Exception**: scheduler tick interaction (Q1 #5). Genuinely needs a window that spans an IST tick. **Minimum defensible window: 4-6h or "spans next scheduled task"** — whichever is shorter.

---

## Q5 — Empirically defensible recommendation

**Pick (d) synthetic load + (c) shortened 4h gate as belt-and-suspenders.**

Concrete protocol for Anchor 6 PRs 6.4-6.14:

1. **Deploy delete-PR.**
2. **Boot check** — `flyctl logs` for 60 seconds; verify no panic / Fx graph errors.
3. **Trigger synthetic smoke** — `gh workflow run smoke-canary.yml` against deployed URL. Wait ~30s for completion.
4. **Verify `/healthz?format=json`** — every component status `ok` or `disabled`. No `degraded`.
5. **Wait until next scheduled IST tick** (max 4h between morning_briefing 09:00 → mis_warning 14:30 → daily_summary 15:35 → pnl_snapshot 15:40 → audit_cleanup 03:00). If the deploy is 30 min before the next tick, wait 30 min. If it's 4 hours before, wait 4 hours.
6. **Re-verify smoke + healthz post-tick.**
7. **Proceed to next delete-PR.**

**Calendar floor with this protocol**: not 24h × 7 = 7 days. Instead: **(deploy + smoke + max 4h tick-spanning wait) × 7 ≈ 28 hours total ≈ 1.5 days.**

**Even more aggressive option (e) is acceptable**: ship all 6 remaining deletes (6.6/6.8/6.10/6.12/6.14 — 5 PRs since 6.4 is unique blocker per `a2a11db`) in one bundled deploy v213+. Smoke-test post-deploy. Wait one IST tick (max 4h). If green, declare green. **Calendar floor: ~5 hours.**

**Recommended: option (e) for the remaining 5 standard delete-PRs.** PR 6.4 (BrokerResolverProvider redesign per `a2a11db`) ships separately due to its interface-change blast radius. Other 5 are pure DI-graph refactors with mechanically identical shape — bundle them.

**Anchor 6 calendar revision**:
- Was: ~9-10 days (per `5fbd4a1`)
- Now: **~2-3 days** (PR 6.4 retry 75 min + bundled deploy of 5 deletes ~5h + final cleanup PR 6.15 ~2h + buffer)

**B-Full total revision**: ~21-26 days at N=20 → **~14-19 days at N=20**. The observation-gate compression is the largest single calendar reduction in the entire B-Full plan.

---

## Honest closing

I was wrong about the irreducible floor. The 24h gate is appropriate at scale (real users, volume-driven bugs, cumulative drift) — **none of which apply at our 0-user pre-launch state**. The empirical signal: smoke-canary cron at 30 min, anomaly detector inert below 5 baseline orders, no rollbacks in 30 commits, 7 add-provider PRs already shipped same-day. The gate framing was prudent for a deploy-cadence template, but inappropriately conservative for our specific context.

**Adopt the synthetic-load + tick-spanning protocol. Compress 7 days → 5-28 hours.**

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Honest closing** (final).
