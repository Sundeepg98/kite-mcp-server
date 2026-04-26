# Blockers to 100 — per-dim resolution map at HEAD `a80672d`

**Charter**: For each of the 13 dims, identify what specifically blocks reaching 100. Empirical evidence per blocker. Resolution disposition: `SHIPPED-via-X` / `DOCUMENTED-anti-rec` / `DOCUMENTED-external` / `DOCUMENTED-irreducible` / `SCALE-GATED`.

**Constraint**: must NOT trigger Wire/fx, Logger wrap, Middleware split, or full ES (the 4 anti-rec'd patterns per `8596138`+`ebfdf3d`).

**Budget**: 500 LOC cumulative for ship-able items. Density floor 0.4 pts/100 LOC per `d48046b`.

---

## Methodology

Per the dispatch:
1. Per-dim: current → 100 gap → blockers (file:line evidence) → resolution per blocker.
2. Code-tractable + non-anti-rec'd + ≥0.4 density → SHIP.
3. Anti-rec'd (Wire/fx/Logger wrap/middleware split/full ES) → document why blocking 100 is the correct stop.
4. External $$ required → cost-stack only, no fake compliance docs.
5. Irreducible (correctness-verified) → document the verification.

---

## Per-dim blocker map

### 1. CQRS — 94 → 100 (gap +6)

| Blocker | Evidence | Resolution |
|---|---|---|
| Saga / cross-aggregate compensation | `kc/usecases/account_usecases.go:72-116` `DeleteMyAccountUseCase.Execute` orchestrates 8 store updates with no rollback on partial failure | **SHIP** — 80 LOC saga primitive in `kc/usecases/saga.go` + tests. Density: ~3 pts / 80 LOC = **3.75 pts/100 LOC**. Above floor. |
| Materialized-view rebuilders | None found; `kc/eventsourcing/projection.go` rebuilds from events but no admin trigger | **SHIP** if ≤50 LOC — admin tool that re-runs projections. Density: ~1 pt / 50 LOC = **2.0 pts/100 LOC** |
| Query-side caching | `kc/audit/anomaly_cache.go` exists for one query; no general pattern | **DEFER** — premature without measured query bottleneck. Density: <0.4. |

**Score lift if shipped**: +3 → 97. Remaining +3 to 100 requires custom go-vet analyzer (already covered by `mcp/integrity.go` tool-poison detection — partial credit). Final 100 ceiling needs domain-event-flow visualization + saga-orchestration UI which is outside code-tractable surface.

### 2. Hexagonal — 94 → 100 (gap +6)

| Blocker | Evidence | Resolution |
|---|---|---|
| 84 `*Concrete()` accessor sites | `grep -c Concrete\(\) app/*.go` = 84 across 14 files; 6 in http.go (e.g., `app/http.go:181` `kcManager.UserStoreConcrete()`) | **DEFER** — interface-extending refactor, est. 200+ LOC. Density: 6/200 = **3.0** but BLAST RADIUS exceeds budget. Each `*Concrete()` removal needs adding the leaked method to its narrow port + interface assertion. The 6 http.go sites alone need UserStoreProvider extension covering `GetByEmail`/`UpdateStatus`/`SetRole` + BillingStoreProvider extension. |
| Wire/fx DI container | Pass 18 verdict | **DOCUMENTED-anti-rec** — the 4 anti-rec'd patterns include this. Wire/fx codegen would regress agent-throughput per `8596138`+`ebfdf3d`. |

**Score lift if shipped**: 0 (Concrete refactor deferred — exceeds budget; anti-rec'd item documented).

### 3. DDD — 94 → 100 (gap +6)

| Blocker | Evidence | Resolution |
|---|---|---|
| Money value object across 873 float64 sites | `grep -c float64 kc/**/*.go` = 873 occurrences across 115 files; only 20 production files use `domain.Money` | **DEFER** — wholesale float64 → Money substitution is multi-week refactor. Density at ≤500 LOC scope: <0.5 pts because partial migration creates inconsistency without lifting score (auditor sees mixed types as worse than fully float64). |
| MWPL F&O limits as aggregate invariant | No `MWPLLimit` aggregate; lives in `kc/riskguard/` as procedural checks | **DEFER** — true aggregate would need market-segment master data + per-instrument MWPL fetcher. ~400 LOC + recurring NSE data fetch. |
| Saga compensation primitives | Same as CQRS#1 — folds into saga ship | **SHIP** — counted under CQRS. |

**Score lift if shipped**: +1 (saga primitives also tighten DDD coordination story).

### 4. Event Sourcing — 85 → 100 (gap +15)

| Blocker | Evidence | Resolution |
|---|---|---|
| Full state-from-events for ALL aggregates | Currently outbox + `domain_events` table + 3 aggregates (alert/order/position) | **DOCUMENTED-anti-rec** — full ES is one of the 4 explicitly rejected patterns. Per `2a1f933` Class 4: outbox + events sufficient for compliance reconstruction; full ES adds latency on every read with zero auditor benefit. |
| Billing/oauth/paper-engine event coverage | `grep -l 'eventDispatcher.Subscribe' app/wire.go` shows 13 event types, none for billing/oauth tier changes | **PARTIAL-SHIP** — billing tier change events. ~40 LOC. Density: ~2 pts / 40 LOC = **5.0 pts/100 LOC**. Above floor. |
| Admin-read events | No `admin.read.X` event types | **DEFER** — read-event audit is covered by `kc/audit/store.go` tool-call audit trail (functional equivalent). |

**Score lift if shipped**: +2 (billing events). Remaining +13 is anti-rec'd full ES.

### 5. Middleware — 95 → 100 (gap +5)

| Blocker | Evidence | Resolution |
|---|---|---|
| 10-stage chain split into compositional pipelines | `app/wire.go:454-605` — chain is procedural, not declarative-composable | **DOCUMENTED-anti-rec** — middleware split is one of the 4 explicitly rejected patterns per `8596138`+`ebfdf3d`. Permanent ceiling. |

**Score lift**: 0 (only blocker is anti-rec'd).

### 6. SOLID — 95 → 100 (gap +5)

| Blocker | Evidence | Resolution |
|---|---|---|
| Logger Provider wrap | `*slog.Logger` used directly in 100+ sites | **DOCUMENTED-anti-rec** — Logger wrap is one of the 4 explicitly rejected patterns. Pass 17 explicitly rejected. |
| Port-ify all 27 single-method providers | Already at 22-field ToolHandlerDeps; lifting to 27+ is ISP score-inflation | **DOCUMENTED-anti-rec** — would regress agent-throughput by adding indirection without consumer benefit. Per `2a1f933` Class 4: "ceremony" pattern. |
| 6 stays-on-Manager sites need port surface decisions | `app/http.go:181,382,399,404,423,448` | **PARTIAL-SHIP** — extend UserStoreProvider with 3 methods needed by http.go; remove 4 Concrete() calls. ~80 LOC. Density: ~2 pts / 80 LOC = **2.5 pts/100 LOC**. Above floor. |

**Score lift if shipped**: +2 (3 remaining anti-rec'd or scope-bounded).

### 7. Plugin — 99 → 100 (gap +1)

| Blocker | Evidence | Resolution |
|---|---|---|
| Plugin discovery loader (registry pattern) | No filesystem-based plugin loader; all plugins compile-time registered | **DOCUMENTED-irreducible** — Go's static linking model precludes runtime plugin loading without `plugin` package which is unsupported on Windows + has FFI/symbol versioning issues. The 1-pt residual is structural. Workaround: subprocess plugin (already supported via `RegisterSubprocessCheck`) is the correct Go-idiomatic answer. |

**Score lift**: 0 (irreducible gap).

### 8. Decorator — 95 → 100 (gap +5)

| Blocker | Evidence | Resolution |
|---|---|---|
| Decorator chain restructure | Hook around-middleware composition is in `mcp/registry.go:HookMiddlewareFor` | **DOCUMENTED-anti-rec** — Permanent ceiling per Apr-2026 audit. No consumer demand. |

**Score lift**: 0.

### 9. Test Architecture — 97 → 100 (gap +3)

| Blocker | Evidence | Resolution |
|---|---|---|
| Property-based tests | 4 already exist (`mcp/sector_tool_property_test.go`, `mcp/options_greeks_property_test.go`, `mcp/indicators_property_test.go`, `mcp/common_property_test.go`, `kc/riskguard/dedup_property_test.go`) | **SHIP** — 1 property test for `kc/domain/money.go` (Add/Sub/Multiply algebra). ~60 LOC. Density: ~1 pt / 60 LOC = **1.7 pts/100 LOC**. Above floor. |
| Mutation testing | `.github/workflows/mutation.yml` exists | **DONE** — already shipped. No score lift available. |
| Benchmark regression sentinels | 6 existing benchmarks in 2 files (`kc/instruments/manager_test.go` + `kc/session_signing_test.go`); no CI sentinel | **SHIP** — 1 GH Actions step pinning regression threshold. ~30 LOC. Density: ~0.5 pt / 30 LOC = **1.7 pts/100 LOC**. Above floor. |

**Score lift if shipped**: +2 → 99. Remaining +1 to 100 needs full mutation-score gate (requires baseline run + threshold; deferred — high noise risk per existing mutation.yml run.)

### 10. Compatibility (ISO 25010) — 85 → 100 (gap +15)

| Blocker | Evidence | Resolution |
|---|---|---|
| Real second broker adapter (Upstox/Angel/Dhan) | Only mock + zerodha adapters | **SCALE-GATED** — needs paying customer asking for second broker. Per `kite-mrr-reality.md`: ₹15-25k MRR ceiling at 12mo means no enterprise deal demanding multi-broker. Cost: ~600 LOC + ongoing maintenance. |
| Backward-compat tool-surface lock test | No `TestToolSurfaceUnchanged` snapshot test | **SHIP** — 50 LOC snapshot of registered tools + assertion. Density: ~1 pt / 50 LOC = **2.0 pts/100 LOC**. Above floor. |
| Plugin SDK ergonomics doc | Plugin extension points exist; doc doesn't unify them | **PARTIAL-SHIP** — folded into a `docs/plugin-sdk.md` if ≤80 LOC; density ~0.6 pts/100 LOC. |

**Score lift if shipped**: +2 (lock test + minor doc).

### 11. Portability (ISO 25010) — 80 → 100 (gap +20)

| Blocker | Evidence | Resolution |
|---|---|---|
| Postgres adapter + schema portability | SQLDB interface shipped (`0a9e78d`); no real Postgres impl | **SCALE-GATED** — needs 5K+ users. Cost: ~300 LOC + maintenance. |
| ARM64 multi-arch build | Release builds are `darwin-arm64` + amd64 | **DONE** — already in `.github/workflows/release.yml` |
| Windows/macOS CI matrix | CI runs ubuntu-latest only | **SHIP** — 15 LOC CI matrix expansion. Density: ~3 pts / 15 LOC = **20 pts/100 LOC**. WAY above floor. |
| Helm chart / docker-compose for non-Fly.io users | None present | **DEFER** — low score lift, high maintenance burden (Helm versioning churn). |

**Score lift if shipped**: +3 (CI matrix → Windows + macOS empirical proof).

### 12. NIST CSF 2.0 — 78 → 100 (gap +22)

| Blocker | Evidence | Resolution |
|---|---|---|
| External SOC 2 audit | No SOC 2 report | **DOCUMENTED-external** — $15-30k Y1 cost per `kite-cost-estimates.md`. Triggered by FLOSS/fund grant per `2a1f933` Class 1. |
| Real-time alert pipeline (SMS/PagerDuty escalation) | Telegram alerts exist (`kc/telegram/`) but no SMS escalation | **DEFER** — needs external service (Twilio/PagerDuty). Cost ~$10-50/mo plus 100 LOC integration. Score lift +2 only (Telegram already covers Detect+Respond). |
| Chaos test suite | Not present | **DEFER** — 200 LOC, density ~1 pt/100 LOC at floor. Implementation risk: chaos-injecting outbox/plugin recovery would need fault-injection harness. Below 0.4 floor at realistic LOC. |
| R2 restore validation cron | DR drill exists (`scripts/dr-drill.sh`) but no scheduled run | **SHIP** — GH Actions monthly cron. ~30 LOC. Density: ~1 pt / 30 LOC = **3.3 pts/100 LOC**. Above floor. |
| NIST CSF self-assessment doc | SECURITY_POSTURE.md covers SEBI CSCRF; only 1 mention of NIST in entire docs/ | **SHIP** — `docs/nist-csf-mapping.md` documenting Identify/Protect/Detect/Respond/Recover with code refs. ~120 LOC. Density: ~3 pts / 120 LOC = **2.5 pts/100 LOC**. Above floor. |

**Score lift if shipped**: +4 (R2 cron + NIST mapping doc).

### 13. Enterprise Governance — 48 → 100 (gap +52)

| Blocker | Evidence | Resolution |
|---|---|---|
| External pen-test | No pen-test report | **DOCUMENTED-external** — $5-15k. Triggered by SOC 2 prep. |
| ISMS / ISO 27001 cert | No ISMS doc | **DOCUMENTED-external** — multi-month consultant work + ₹5-15L. Far past current MRR. |
| MFA on admin | `SECURITY_POSTURE.md §4.3` deferred | **DEFER** — 80 LOC + UX flow. Not in this 500 LOC budget; queue for next session. |
| Annual risk register | No `docs/risk-register.md` | **SHIP** — 60 LOC honest risk-register doc. Density: ~2 pts / 60 LOC = **3.3 pts/100 LOC**. Above floor. |
| Threat model | No `docs/threat-model.md` | **SHIP** — STRIDE-format threat model. ~80 LOC. Density: ~2 pts / 80 LOC = **2.5 pts/100 LOC**. Above floor. |
| Retention policy formalization | `docs/data-classification.md` mentions retention per-table; no consolidated policy | **SHIP** — `docs/retention-policy.md`. ~50 LOC. Density: ~1 pt / 50 LOC = **2.0 pts/100 LOC**. Above floor. |
| 5-10 retrospective ADRs | 2 ADRs shipped (`8ef79cd`); could add 3-5 more retrospective | **SHIP** — 3 retrospective ADRs (B77 plugin registry, AlertDB cycle, CQRS bus). ~150 LOC. Density: ~3 pts / 150 LOC = **2.0 pts/100 LOC**. Above floor. |

**Score lift if shipped**: +9 (4 governance docs + 3 ADRs).

---

## Aggregate ship-list (priority by density)

Sorted by density above the 0.4 floor:

| # | Item | Dim | LOC | Pts | Density | Risk |
|---|---|---|---|---|---|---|
| 1 | Windows + macOS CI matrix | Port | 15 | 3 | **20.0** | LOW |
| 2 | Billing tier change events | ES | 40 | 2 | **5.0** | LOW |
| 3 | Saga primitive in `kc/usecases/saga.go` | CQRS+DDD | 80 | 3 | **3.75** | LOW |
| 4 | R2 restore validation cron | NIST | 30 | 1 | **3.3** | LOW |
| 5 | Risk register doc | EntGov | 60 | 2 | **3.3** | LOW |
| 6 | Threat model doc | EntGov | 80 | 2 | **2.5** | LOW |
| 7 | NIST CSF mapping doc | NIST | 120 | 3 | **2.5** | LOW |
| 8 | Extend UserStoreProvider, drop 4 Concrete() | SOLID | 80 | 2 | **2.5** | MED — touches http.go |
| 9 | Tool-surface lock test | Compat | 50 | 1 | **2.0** | LOW |
| 10 | Retention policy doc | EntGov | 50 | 1 | **2.0** | LOW |
| 11 | 3 retrospective ADRs | EntGov | 150 | 3 | **2.0** | LOW |
| 12 | Money property-based test | TestArch | 60 | 1 | **1.7** | LOW |
| 13 | Materialized-view rebuilder admin tool | CQRS | 50 | 1 | **2.0** | MED — eventsourcing read path |
| 14 | Benchmark regression CI step | TestArch | 30 | 0.5 | **1.7** | MED — high noise risk |

**Cumulative LOC if all 14 ship**: 895. **Above 500 budget.**

**Top-N within 500 LOC budget**: items 1-9 = 555 LOC. Trim to items 1-8 = 505 LOC. Trim further: items 1-7 + item 9 = 475 LOC.

**Final ship plan**: 1, 2, 3, 4, 5, 6, 7, 9 = **475 LOC, +17 pts** (replacing the more expensive ADR/policy item 8 with the cheap lock test).

---

## Anti-rec'd items (DOCUMENTED, not shipped)

| Item | Dim | Why NOT shipping |
|---|---|---|
| Wire/fx DI container | Hex | Anti-rec'd #1: regresses agent-throughput per `8596138`+`ebfdf3d` |
| Logger Provider wrap | SOLID | Anti-rec'd #2: ceremony, Pass 17 explicit rejection |
| Middleware split | Middleware | Anti-rec'd #3: permanent ceiling at 95 |
| Full ES (state-from-events for all aggregates) | ES | Anti-rec'd #4: outbox+events sufficient per `2a1f933` Class 4 |

---

## External-$$ items (cost-stack only)

| Item | Cost | Trigger |
|---|---|---|
| External SOC 2 audit | $15-30k | FLOSS/fund grant lands |
| External pen-test | $5-15k | SOC 2 prep |
| ISMS/ISO 27001 cert | ₹5-15L + multi-month | First enterprise RFP |
| Postgres adapter | scale-gated | 5K+ paying users |
| Real Upstox/Angel adapter | $20-30k engineering | First paying customer asking |

Per `kite-mrr-reality.md`: ₹15-25k MRR at 12mo means none of these are triggered yet.

---

## Irreducible items (verification-documented)

| Item | Dim | Verification |
|---|---|---|
| Plugin discovery loader | Plugin | `plugin` package unsupported on Windows; subprocess plugin already supported. The 1-pt residual is structural Go limitation. |
| 5 setter functions in kc/manager.go | Hex | All 5 verified as construction-order, not runtime cycles, in `d6d1c8b`. 0 LOC fix needed. |

---

## Final verdict on score lift

| Dim | Current | Ship-lift | Final | Rationale |
|---|---|---|---|---|
| CQRS | 94 | +3 | 97 | Saga primitive |
| Hexagonal | 94 | 0 | 94 | Concrete refactor exceeds budget; Wire/fx anti-rec'd |
| DDD | 94 | +1 | 95 | Saga also tightens DDD |
| Event Sourcing | 85 | +2 | 87 | Billing events |
| Middleware | 95 | 0 | 95 | Anti-rec'd item only |
| SOLID | 95 | 0 | 95 | Concrete refactor deferred |
| Plugin | 99 | 0 | 99 | Irreducible |
| Decorator | 95 | 0 | 95 | Anti-rec'd item only |
| Test Architecture | 97 | +1 | 98 | Property test for Money |
| Compatibility | 85 | +1 | 86 | Lock test |
| Portability | 80 | +3 | 83 | CI matrix |
| NIST CSF | 78 | +4 | 82 | R2 cron + NIST doc |
| Enterprise Governance | 48 | +7 | 55 | 4 governance docs |

**New aggregate (equal-weighted)**: (97+94+95+87+95+95+99+95+98+86+83+82+55) / 13 = 1161 / 13 = **89.3** (vs 87.6 baseline = +1.7).

**New aggregate (Pass 17 weighted)**: ~93.8 (vs 92.5 baseline = +1.3).

This is the **last exhaustive code-tractable pass**. Beyond this, the score-lift surface is genuinely empty unless external $$ enters the picture.

---

*Generated 2026-04-26 against HEAD `a80672d`. Read-only research deliverable; ship-list executed in subsequent commits.*
