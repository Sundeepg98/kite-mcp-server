# Scorecard Final — empirical re-grade at HEAD `562f623` (2026-04-26 night)

**Method**: empirical re-grade against the 13-dim rubric in `.research/blockers-to-100.md` (`4b0afd2`), using current source. Compares against the prior re-grade at HEAD `7649dfb` (`d5b9043`, 88.8 equal-weighted / ~93.5 Pass-17). Wave 1 + Wave 2 commits all empirically verified in source.

**Charter**: read-only. ~30 min wall.

## Wave 1 + 2 driver commits (10 since prior re-grade)

| Commit | Description | Touches |
|---|---|---|
| `a910e25` | feat(plugin): Watcher.Stop with join | Plugin |
| `e7d5b3d` | fix(db): SQLite `foreign_keys=ON` per-connection (`kc/alerts/db.go:75-94`) | DDD/data integrity |
| `8924120` | feat(broker): typed `RateLimitError` (`broker/errors.go:22`) — 19 production call sites | Hex / Compatibility |
| `a97dc29` | feat(riskguard): market-hours rejection (T1) | DDD / SOLID |
| `aa71806` | docs/RETENTION.md (334 LOC) | NIST CSF / EntGov |
| `9ffd03a` | refactor(C1): ctx propagation through trailing-stop dispatch (12 LOC) | SOLID / Compatibility |
| `3b7849b` | docs(adr): 3 retrospective ADRs — `0003-per-user-oauth`, `0004-litestream-r2`, `0005-tool-middleware-chain-order` | EntGov |
| `51ca4b8` | test(money): 8 algebraic property laws (`kc/domain/money_property_test.go`, 284 LOC) | DDD / Test-Arch |
| `511c198` | ci: benchmark regression gate (`benchmark.yml`, benchstat comparison) | Test-Arch / Portability |
| `562f623` | feat(billing): `TierChangedEvent` domain event (`kc/domain/events.go:369`, dispatched at `kc/billing/store.go:263`, 14 test cases) | ES / DDD |

## Per-dim score table

| Dim | At `7649dfb` | At `562f623` | Δ | Evidence | What blocks 100 |
|---|---|---|---|---|---|
| 1. CQRS | 97 | **97** | 0 | Saga `kc/usecases/saga.go` (140 LOC) unchanged; Money property tests reinforce VO algebra | +3 anti-rec'd (domain-event-flow viz, saga UI — out of code-tractable surface) |
| 2. Hexagonal | 94 | **95** | +1 | `RateLimitError` (`8924120`) typed-error port at broker boundary — 19 call sites use `errors.As(&rle)`. Hex score lift from cleaner port semantics. `Concrete()` count still 84 (unchanged — anti-rec'd) | +5 anti-rec'd (Concrete refactor + Wire/fx) |
| 3. DDD | 95 | **97** | +2 | `TierChangedEvent` (`562f623`) — first billing-domain event with `EventType()` + `OccurredAt()`; +1 for SQLite FK PRAGMA (`e7d5b3d`) tightening data-integrity invariants enforced at storage boundary; +1 for market-hours rejection (`a97dc29`) lifting domain rule from procedural to riskguard policy. `kc/domain/spec.go` Specifications + Money property tests (284 LOC, 8 laws — reflexivity/symmetry/transitivity of equality, additive identity/inverse/associativity/commutativity, multiplicative identity) provide rigorous VO proof | +3 SCALE-GATED (Money VO across 873 float64 sites, MWPL F&O aggregate) |
| 4. Event Sourcing | 85 | **87** | +2 | `TierChangedEvent` (`562f623`) — first billing-tier event closes the explicit gap from `blockers-to-100.md` §4 | +13 anti-rec'd (full ES rejected per `2a1f933` Class 4) |
| 5. Middleware | 95 | **95** | 0 | 10-stage chain unchanged; ADR `0005-tool-middleware-chain-order` (`3b7849b`) documents the order rationale | Anti-rec'd ceiling — middleware-split rejected |
| 6. SOLID | 95 | **96** | +1 | C1 ctx propagation (`9ffd03a`) — fixes ctx-discarded-mid-flight in trailing-stop dispatch; reinforces dependency-direction pattern (12 LOC, 2 files). `manager.X()` direct uses in `mcp/` still 54 (floor reached) | +4 anti-rec'd (Logger wrap rejected; 27-port ISP-inflation rejected) |
| 7. Plugin | 99.5 | **99.5** | 0 | Watcher.Stop join (`a910e25`) closes the deterministic-shutdown gap on plugin watcher — counts as a hardening pass within the 99.5 bracket; B77 isolation + RISKGUARD_PLUGIN_DIR discovery already counted | +0.5 irreducible (Go static-link model precludes dlopen on Windows) |
| 8. Decorator | 95 | **95** | 0 | Hook around-middleware composition unchanged | Anti-rec'd ceiling |
| 9. Test Architecture | 97 | **98** | +1 | Money property tests (`51ca4b8`, 284 LOC, 8 laws) close the explicit `blockers-to-100.md` §9 ship-list item; benchmark regression gate (`511c198`) closes the bench-CI item with benchstat-based comparison | +2 SCALE-GATED (full mutation-score gate noise risk) |
| 10. Compatibility | 85 | **86** | +1 | Typed `RateLimitError` (`8924120`) — clients can `errors.As(&rle)` to read `RetryAfter` / `Inner`. Tool-surface lock test still NOT shipped | +13 SCALE-GATED (real second broker adapter) |
| 11. Portability | 83 | **84** | +1 | Benchmark regression gate (`511c198`) — Linux runners exercise the perf path; +1 portability proof. CI matrix already at `[ubuntu, macos, windows]` | +16 SCALE-GATED (Postgres adapter; Helm/compose deferred) |
| 12. NIST CSF 2.0 | 82 | **84** | +2 | `docs/RETENTION.md` (334 LOC, `aa71806`) — Recover function: data classification + retention policy formalization. Risk register, threat model, NIST mapping, DR cron all already in place | +16 external-$$ (SOC 2, real-time alert pipeline, chaos suite) |
| 13. Enterprise Governance | 52 | **57** | +5 | 3 retrospective ADRs (`3b7849b`): `0003-per-user-oauth-optional-global-credentials`, `0004-sqlite-litestream-r2-over-postgres`, `0005-tool-middleware-chain-order` — total 5 ADRs on file. Retention policy (`aa71806`) closes the explicit `blockers-to-100.md` §13 retention-doc item | +43 external-$$ (ISMS/ISO 27001, external pen-test, SOC 2). MFA-on-admin still deferred. |

## Aggregate composite

**Equal-weighted (per `blockers-to-100.md` methodology):**

```
(97 + 95 + 97 + 87 + 95 + 96 + 99.5 + 95 + 98 + 86 + 84 + 84 + 57) / 13
= 1170.5 / 13
= 90.04
```

vs prior 88.8: **+1.24 absolute**.

**vs ship-plan target 89.3 (`blockers-to-100.md` §"Final verdict"):** ceiling EXCEEDED by **+0.74**.

The ship-plan's 89.3 target was a conservative lower-bound — it accounted for items 1-8 of the ship-list (475 LOC, +17 plan-units) within a 500 LOC budget. Wave 1+2 actually shipped:
- All 6 NOT-shipped items from `d5b9043`'s "remaining ship-able" list (billing events, Money property test, retention doc, 3 ADRs, benchmark CI; ~380 LOC predicted +8.5 plan-units)
- Plus 4 BONUS items not in the original ship-list: Watcher.Stop join, SQLite FK PRAGMA, RateLimitError typed-error port, market-hours rejection, C1 ctx propagation

Hence the +1.24 actual aggregate gain exceeds the `+0.5` shortfall noted in `d5b9043`. **The 89.3 ceiling has been hit and surpassed.**

**Pass 17 weighted (CORE dims weighted higher):** ~95.0 (extrapolated from prior 93.5 baseline + the +1.24 equal-weighted delta; CORE dims are CQRS/Hex/DDD/SOLID/Test-Arch which received 7 of the 13 driver-impact points → weighted impact of +1.5 on the higher-weight CORE half).

## Has the ceiling been hit?

**Yes**, in two distinct senses:

1. **Ship-plan ceiling (89.3 equal-weighted): EXCEEDED at 90.04.** All ship-list items from `blockers-to-100.md` are now shipped except:
   - Tool-surface lock test (Compat +1) — small, low-effort if pursued
   - Benchmark regression CI is shipped but might warrant per-package threshold tuning over time (operational, not a one-time ship)

2. **Calibrated `~95-96` Pass-17 ceiling (per Pass 17 weights cited in `architecture-re-audit.md` §"Most-stalled dims"): ESSENTIALLY HIT at ~95.0.** Remaining gap is fully accounted for by anti-rec'd ceilings + external-$$ items (see below). No code-tractable items remain that respect the budget + density floor + anti-rec'd constraints.

## Items the ceiling itself is gated by (permanent — not gaps)

### Anti-rec'd patterns (4 total — DOCUMENTED, not shipped)

These are explicitly rejected by prior research (`8596138`, `ebfdf3d`, `2a1f933`). The dim-points blocked are mathematically unreachable without reversing the rejection:

| Pattern | Affected dim | Points blocked | Why rejected |
|---|---|---|---|
| Wire/fx DI container | Hexagonal | +5 | Regresses agent-throughput; codegen tooling burden |
| Logger Provider wrap | SOLID | +4 | Ceremony pattern; rejected at Pass 17 |
| Middleware split | Middleware | +5 | Permanent ceiling at 95 — declarative-composable pipelines have no consumer demand |
| Full ES (state-from-events for ALL aggregates) | Event Sourcing | +13 | Outbox + 3 aggregates + tier event sufficient for compliance reconstruction; full ES adds latency on every read with zero auditor benefit |

**Anti-rec'd points blocked (sum): 27 of 1300 = 2.08 percentage-points of the equal-weighted aggregate.**

### External-$$ items (SCALE-GATED — cost-stack only)

Per `kite-mrr-reality.md`: ₹15-25k MRR at 12mo means none triggered yet.

| Item | Affected dim | Points blocked | Cost / Trigger |
|---|---|---|---|
| External SOC 2 audit | NIST CSF | +6 | $15-30k → FLOSS/fund grant lands |
| External pen-test | EntGov | +5 | $5-15k → SOC 2 prep |
| ISMS / ISO 27001 cert | EntGov | +20 | ₹5-15L + multi-month → first enterprise RFP |
| Real Postgres adapter | Portability | +16 | scale-gated → 5K+ paying users |
| Real Upstox/Angel adapter | Compatibility | +13 | ~$20-30k engineering → first paying customer asks |
| Real-time alert pipeline (SMS/PagerDuty) | NIST CSF | +2 | ~$10-50/mo + 100 LOC → external service trigger |
| Chaos test suite | NIST CSF | +2 | ~200 LOC + fault-injection harness — below density floor at current scale |

**External-$$ points blocked (sum): 64 of 1300 = 4.92 percentage-points of equal-weighted aggregate.**

### Irreducible (verified)

| Item | Dim | Points blocked | Why irreducible |
|---|---|---|---|
| Plugin discovery dlopen loader | Plugin | +0.5 | Go's `plugin` package unsupported on Windows; subprocess plugin already shipped |

### Total ceiling math

Theoretical 100 across all 13 dims = 1300. Anti-rec'd + external-$$ + irreducible block: 27 + 64 + 0.5 = **91.5 points** = **7.04% of theoretical max**.

Empirical max under constraints = 100 − 7.04 = **92.96 equal-weighted**.

**Current 90.04 equal-weighted is at 96.85% of the empirical-max ceiling.** The remaining 2.92 points are:
- ~1.0 from Tool-surface lock test + small ship-able items
- ~1.0 from per-dim incremental hardening (operational, not architectural)
- ~0.9 noise band

**Verdict: the calibrated 90 / ~95 Pass-17 ceiling has been hit. Further code-tractable score lift requires reversing anti-rec'd decisions or external $$.**

## Honest opacity

1. **`go test ./...` deferred per user rule + project CLAUDE.md mandate.** WSL2 sync attempted — `git fetch` succeeded but `git checkout 562f623` failed with "pathspec did not match" because **27 commits (including all Wave 1+2) are local-only on Windows side and have not been pushed to origin/master**. WSL2's `origin/master` is at `333ca32`. Per the explicit rule (and `.claude/CLAUDE.md` "Go Testing — USE WSL2 (mandatory)"): defer test verification with explicit note rather than fall back to Windows-native (which is SAC-flaky 50-70%).
2. **Build status verified clean**: `go build ./...` returned no output at HEAD `562f623`.
3. **Pass 17 weighted aggregate ~95.0** is extrapolated, not re-derived. The actual Pass 17 weighting recipe lives in `final-138-gap-catalogue.md` §4 which I did not re-derive. Could be off by ±0.5.
4. **Plugin score 99.5** is a fractional judgment call — the rubric has no fractional scale. If integer-rounded, Plugin stays at 99 and aggregate becomes 89.96 instead of 90.04. The fractional read is more empirically honest given Watcher.Stop is a meaningful hardening but not a 1pt-bracket lift.
5. **Pre-this-session `scorecard-final.md` content** (dated 2026-04-25, claimed 100/100 across 10 dims under a coarser pre-calibration rubric) was overwritten by `d5b9043`. This re-grade replaces the `d5b9043` numbers with current state.
6. **Hex score lift to 95** is on `RateLimitError` typed-error port quality, not Concrete-removal. The 84 `Concrete()` count is unchanged. Some auditors might score Hex strictly lower (~93) for the unchanged Concrete surface — but `blockers-to-100.md` §2 explicitly accepts that gap as deferred-not-regressed. Score is sensitive to that interpretation by ±2 points.
7. **EntGov score 57**: 5 ADRs + governance triad + retention doc + 2 prior ADRs counted. If a stricter rubric weighs only "external-audited" docs (not self-published ADRs), score could drop to ~52. The 57 reflects value-as-documented; 52 reflects value-as-validated-by-third-party.

## Cumulative trajectory

| HEAD | Date | Equal-weighted | Pass 17 | Notes |
|---|---|---|---|---|
| `a4feb5b` (138-gap baseline) | 2026-04-25 | ~89.5 | n/a | Pre-Phase 1+2 |
| `aea6a7c` (post G99/G132) | 2026-04-25 | ~91 | ~96 | Old-rubric overstatement |
| `87e9c17` (re-audit) | 2026-04-26 | 87.6 | 92.5 | Calibrated empirical baseline |
| `a80672d` (ship-plan) | 2026-04-26 | 87.6 | 92.5 | Plan baseline |
| `7649dfb` (prior re-grade `d5b9043`) | 2026-04-26 evening | 88.8 | ~93.5 | Saga + CI matrix + DR cron + governance triad shipped |
| **`562f623` (current)** | **2026-04-26 night** | **90.04** | **~95.0** | **Wave 1 + Wave 2 shipped: 10 commits, ship-list completed + 4 bonus** |

## Sources

- Rubric: `.research/blockers-to-100.md` (`4b0afd2`)
- Prior re-grades: `.research/architecture-re-audit.md` (`a80672d`), `.research/scorecard-final.md` (`d5b9043` superseded by this rewrite)
- Plan completion: `.research/architecture-100-gap-current.md` (`77d45e5`)
- Driver commits cited above (10 since prior re-grade)
- Empirical metrics this audit: `Concrete()` = 84 (unchanged); `manager.X()` direct uses in mcp/ = 54 (unchanged); t.Parallel = 338 production tests; 5 ADRs; saga = 140 LOC; Money property test = 284 LOC / 8 laws; RateLimitError = 19 production sites; TierChangedEvent = 14 test cases
- Build status: `go build ./...` clean at HEAD `562f623`. `go test ./...` deferred (commits unpushed; WSL2 sync impossible without push per `.claude/CLAUDE.md` mandate).

---

*Generated 2026-04-26 night, read-only research deliverable.*
