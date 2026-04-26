# Scorecard Final — empirical re-grade at HEAD `7649dfb` (2026-04-26 evening)

**Method**: empirical re-grade against the rubric in `.research/blockers-to-100.md` (`4b0afd2`), using current source state. Compares against the per-dim audit at HEAD `87e9c17` (`.research/architecture-re-audit.md`) and the ship-plan derived from HEAD `a80672d`.

**Charter**: read-only. ~30 min wall.

**Prior `scorecard-final.md` content** (dated 2026-04-25 at HEAD `182ff0f`, pre-rubric-calibration) was overwritten by this re-grade. The pre-2026-04-25 scorecard claimed all 10 dims at 100/100 under a coarser rubric; this re-grade uses the calibrated 13-dim rubric with the anti-rec'd-aware ceiling.

## Per-dim score table

| Dim | At `87e9c17` | Ship-plan target | At `7649dfb` | Δ from baseline | Evidence | What blocks 100 |
|---|---|---|---|---|---|---|
| 1. CQRS | 94 | 97 (saga) | **97** | +3 | `kc/usecases/saga.go` (140 LOC, commit `f1a8058`) — BASE-style saga primitive with `SagaStep{Action, Compensate}`, BestEffort + ContinueOnError, Garcia-Molina & Salem 1987 citation | +3 to 100: domain-event-flow viz + saga-orchestration UI (out of code-tractable surface per `blockers-to-100.md` §1) |
| 2. Hexagonal | 94 | 94 (Concrete refactor deferred) | **94** | 0 | 84 `Concrete()` accessor sites in `app/*.go` (unchanged from `87e9c17`); Wire/fx anti-rec'd | +6 to 100: 200 LOC `Concrete()` removal across 14 files (DEFER per §2 — exceeds 500 LOC budget; Wire/fx remains anti-rec'd) |
| 3. DDD | 94 | 95 (saga also tightens DDD) | **95** | +1 | Same `kc/usecases/saga.go` — saga is a coordination primitive that domain aggregates can compose. `kc/domain/spec.go` Specifications still well-realized. | +5 to 100: Money VO across 873 float64 sites, MWPL F&O aggregate (both DEFER per §3 — multi-week refactor risk + scale-gated NSE data) |
| 4. Event Sourcing | 85 | 87 (billing events) | **85** | 0 | Billing tier-change event emission NOT shipped (no `kc/eventsourcing/billing*.go`). Outbox + 3 aggregates unchanged | +13 anti-rec'd (full ES rejected per `2a1f933` Class 4); +2 ship-able (billing events) NOT yet shipped |
| 5. Middleware | 95 | 95 | **95** | 0 | 10-stage chain unchanged; B77 `HookMiddlewareFor` consumes per-App registry (`931b6bd`). Permanent ceiling. | Anti-rec'd ceiling — middleware-split rejected per `8596138` |
| 6. SOLID | 95 | 95 (Concrete deferred) | **95** | 0 | 22-field `ToolHandlerDeps` ISP unchanged. 54 `manager.X()` direct uses in `mcp/*.go` (was ~165 pre-Phase-3a; floor reached) | +5 to 100: anti-rec'd (Logger wrap rejected; 27-port ISP-inflation rejected) |
| 7. Plugin | 99 | 99 | **99.5** | +0.5 | B77 + `feat(riskguard): plugin discovery via RISKGUARD_PLUGIN_DIR manifest` (`333ca32`) — wasn't in ship-plan but lifts plugin discovery story by half-point | Irreducible per §7 — `plugin` package unsupported on Windows; subprocess plugin already shipped |
| 8. Decorator | 95 | 95 | **95** | 0 | Hook around-middleware composition unchanged. | Anti-rec'd ceiling |
| 9. Test Architecture | 97 | 98 (Money property test) | **97** | 0 | 414 t.Parallel calls / 375 test files; 5 property tests; mutation.yml + race + goleak. Money property test NOT shipped. | +3 to 100: Money property test (~60 LOC, NOT yet shipped); benchmark regression CI sentinel (~30 LOC, NOT shipped); full mutation-score gate (DEFER, high noise risk) |
| 10. Compatibility | 85 | 86 (lock test) | **85** | 0 | broker.Client composite interface + ADR 0001 unchanged. Tool-surface lock test NOT shipped. | +14 SCALE-GATED (real second broker adapter — ₹15-25k MRR insufficient); +1 ship-able (lock test) NOT yet shipped |
| 11. Portability | 80 | 83 (CI matrix) | **83** | +3 | `.github/workflows/ci.yml` matrix expanded to `[ubuntu-latest, macos-latest, windows-latest]` (commit `18f85f7`) | +17 SCALE-GATED (Postgres adapter); Helm/compose deferred (low ROI) |
| 12. NIST CSF 2.0 | 78 | 82 (R2 cron + NIST doc) | **82** | +4 | `.github/workflows/dr-drill.yml` monthly cron (`43cc844`); `docs/nist-csf-mapping.md` (commit `04f311e`) | +18 external-$$ (SOC 2 audit, real-time alert pipeline, chaos test suite) |
| 13. Enterprise Governance | 48 | 55 (4 governance docs) | **52** | +4 | `docs/risk-register.md` + `docs/threat-model.md` + `docs/nist-csf-mapping.md` (commit `04f311e`, "governance triad"). 2 ADRs unchanged. **NOT shipped**: retention-policy doc (+1), 3 retrospective ADRs (+6) | +48 external-$$ (ISMS/ISO 27001, external pen-test, SOC 2). +7 ship-able remaining |

## Aggregate composite

**Equal-weighted (per `blockers-to-100.md` methodology):**

```
(97 + 94 + 95 + 85 + 95 + 95 + 99.5 + 95 + 97 + 85 + 83 + 82 + 52) / 13
= 1154.5 / 13
= 88.8
```

vs `87e9c17` baseline 87.6 (`architecture-re-audit.md`): **+1.2 absolute**.

vs ship-plan target 89.3 (`blockers-to-100.md` §"Final verdict"): **0.5 short** of target.

The 0.5pt gap maps to NOT-yet-shipped items: billing tier-change events (ES +2), Money property test (TestArch +1), tool-surface lock test (Compat +1), retention policy doc (EntGov +1), 3 retrospective ADRs (EntGov +6). Net unrealized: +11pt against the rubric's individual items, distributed across 5 dims that average to ~0.5pt aggregate impact.

**Pass 17 weighted (CORE dims weighted higher):** ~93.5 (extrapolated from prior session-end claim of 92.5 + lift from saga + governance triad + CI matrix + DR cron).

## What changed since `87e9c17` audit

| Driver commit | Description | Dim impact |
|---|---|---|
| `f1a8058` | feat(usecases): saga primitive for cross-aggregate compensation | CQRS +3, DDD +1 |
| `18f85f7` | ci: expand test matrix to ubuntu+macos+windows | Portability +3 |
| `43cc844` | ci(dr): monthly R2 restore validation cron | NIST +1 |
| `04f311e` | docs: governance triad — risk register + threat model + NIST CSF mapping | NIST +3, EntGov +4 |
| `333ca32` | feat(riskguard): plugin discovery via RISKGUARD_PLUGIN_DIR manifest | Plugin +0.5 |
| (B77 series) | already counted in `87e9c17` baseline | n/a |

**Net delta: +12.5pts across 5 dims; aggregate +1.2pt equal-weighted.**

## What remains ship-able (delta to `blockers-to-100.md` 89.3 target)

| Item | Dim | LOC | Pts | Status |
|---|---|---|---|---|
| Billing tier-change events | ES | ~40 | +2 | NOT shipped |
| Money property-based test | TestArch | ~60 | +1 | NOT shipped |
| Tool-surface lock test | Compat | ~50 | +1 | NOT shipped |
| Retention policy doc | EntGov | ~50 | +1 | NOT shipped |
| 3 retrospective ADRs (B77, AlertDB, CQRS bus) | EntGov | ~150 | +3 | NOT shipped |
| Benchmark regression CI step | TestArch | ~30 | +0.5 | NOT shipped |
| **Total** | | **~380** | **+8.5** | |

These are the dispatch-able units left for an execution agent if the orchestrator wants to chase the 89.3 (equal-weighted) target. Each is independent (no cross-deps), all parallelizable.

## Anti-rec'd (do not ship)

Unchanged from `blockers-to-100.md`:
- Wire/fx DI container (Hex)
- Logger Provider wrap (SOLID)
- Middleware split (Middleware)
- Full ES (state-from-events for all aggregates) (ES)

These remain permanent ceilings. 100 for affected dims is mathematically unreachable without reversing those decisions.

## External-$$ (cost-stack only)

Unchanged from `blockers-to-100.md`:
- External SOC 2 audit ($15-30k) → triggered by FLOSS/fund grant
- External pen-test ($5-15k) → triggered by SOC 2 prep
- ISMS/ISO 27001 cert (₹5-15L) → triggered by enterprise RFP
- Real Postgres adapter → 5K+ paying users
- Real Upstox/Angel adapter → first paying customer asking

Per `kite-mrr-reality.md`: ₹15-25k MRR at 12mo means none triggered yet.

## Honest opacity

1. **`go test ./...` not run.** Windows-side tests are SAC-flaky 50-70% per prior session findings; clean run requires WSL2 (per `8e6d59d` runbook). Δ verifications rely on `git log`, `grep`, `wc -l`, and `go build ./...` (clean). **A clean test run could surface regressions that lower the 97 TestArch score; not verified.**

2. **Pass 17 weights not re-applied.** Cited weighted aggregate ~93.5 by extrapolation from `87e9c17`'s 92.5 + the +1.2 equal-weighted delta. The actual Pass 17 weighting recipe lives in `final-138-gap-catalogue.md` §4 which I did not re-derive. Could be off by ±0.5.

3. **Hex score unchanged at 94.** Trusting `87e9c17`'s baseline. The 84 `Concrete()` count is unchanged since that audit, and no Concrete-removal commits landed; the score should be stable. If a stricter rubric counts each `Concrete()` as a violation, the empirical 94 score may drift down — but `blockers-to-100.md` §2 explicitly accepts this gap as deferred-not-regressed.

4. **The 99.5 Plugin score uses fractional points.** The +0.5 lift from `feat(riskguard): plugin discovery` is my judgment call; the rubric has no fractional scale. If rounded, Plugin stays at 99 and aggregate becomes 88.7 instead of 88.8.

5. **No verification of governance triad doc QUALITY.** Confirmed the files exist and the commit message describes them; did not audit content for completeness vs an enterprise rubric. EntGov sensitivity to doc quality is high — if these docs are placeholder-grade, EntGov should be 50 not 52.

6. **Pre-this-session `scorecard-final.md` content** (dated 2026-04-25 at HEAD `182ff0f`, claimed 100/100 across all 10 dims) was overwritten. That older scorecard used a 10-dim coarser rubric and predates the 13-dim calibration in `87e9c17`. The two are not directly comparable; the present score is the calibrated empirical reality.

## Cumulative trajectory

| HEAD | Date | Equal-weighted | Pass 17 weighted | Notes |
|---|---|---|---|---|
| `a4feb5b` (138-gap baseline) | 2026-04-25 | ~89.5 | n/a | Pre-Phase 1+2 |
| `aea6a7c` (post G99/G132) | 2026-04-25 | ~91 | ~96 | Post final batch |
| `87e9c17` (re-audit) | 2026-04-26 | 87.6 | 92.5 | Empirical re-grade w/ honest equal weighting |
| `a80672d` (ship-plan) | 2026-04-26 | 87.6 | 92.5 | Plan baseline |
| **`7649dfb` (current)** | **2026-04-26 evening** | **88.8** | **~93.5** | **Saga + CI matrix + DR cron + governance triad shipped; +1.2 equal-weighted** |

## Sources

- Rubric: `.research/blockers-to-100.md` (`4b0afd2`)
- Prior re-audit: `.research/architecture-re-audit.md` (`a80672d`)
- Plan completion: `.research/architecture-100-gap-current.md` (`77d45e5`)
- Driver commits cited above
- Empirical metrics this audit: `Concrete()` = 84; `manager.X()` direct uses in mcp/ = 54; t.Parallel = 414 / 375 files; saga = 140 LOC
- Build status: `go build ./...` clean

---

*Generated 2026-04-26 evening, read-only research deliverable.*
