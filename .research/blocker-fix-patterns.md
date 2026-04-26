# Per-Blocker Fix Patterns — 4 Unresolved Wire Blockers

**Context**: Detailed concrete-fix recipes per blocker. Cross-references `ebfdf3d` (prior verification) + `9c1eeae` (A's lifecycle work). Audited HEAD `ebfdf3d`.

**Charter**: Read-only. No source files modified.

**Scope**: 4 blockers preventing Wire/fx adoption beyond Step 1. Goal: identify what's tractable today vs deferred vs irreducible.

---

## Blocker 1 — Runtime conditionals × 6

### Enumeration

| # | File:line | Conditional | Classification |
|---|---|---|---|
| 1 | `app/wire.go:121` | `if alertDB := kcManager.AlertDB(); alertDB != nil` | **(c) runtime-state-dependent** — DB presence is operator config |
| 2 | `app/wire.go:131` | `if app.Config.OAuthJWTSecret != ""` | **(b) deployment-mode** — env-driven, hosted vs local |
| 3 | `app/wire.go:124, 134, 174, 178, 224, 235` | `if !app.DevMode { return fatal }` else log | **(b) deployment-mode** — fail-closed prod / fail-open dev |
| 4 | `app/wire.go:351` | `if alertDB := kcManager.AlertDB(); alertDB != nil` (paperEngine) | **(c) runtime-state** — same root as #1 |
| 5 | `app/wire.go:445` | `if app.Config.StripeSecretKey != "" && !app.DevMode` | **(b) deployment-mode** — billing presence flag |
| 6 | `app/wire.go:516, 555` | `if paperEngine != nil` | **(c) runtime-state** — derived from #4 |

### Fix patterns

**Category (b) — deployment-mode (4 of 6)**: env-driven providers with nil-returns ARE the idiomatic fix. Already implemented for billing (`if Config.StripeSecretKey == "" → no billing middleware`). The `DevMode` fail-closed/fail-open dichotomy is intentional; Wire/build-tags would force build-time variance, defeating single-binary deploy across modes.

**Category (c) — runtime-state-dependent (2 of 6)**: `alertDB != nil` and `paperEngine != nil` are derived from operator config (whether `ALERT_DB_PATH` is set + sub-features). NOT fixable without explicit operator-mode flags driving construction.

### Per-conditional verdict

| # | Tractable today? | Pattern | LOC |
|---|---|---|---|
| 1 | NO | Already idiomatic (`AlertDB() != nil` is the seam) | 0 |
| 2 | NO | Single env-flag, single `if` — refactor adds zero value | 0 |
| 3 | NO | `DevMode` fail-mode dichotomy is intentional | 0 |
| 4 | NO | Same as #1 | 0 |
| 5 | NO | Already idiomatic | 0 |
| 6 | NO | Derived state, not a primary conditional | 0 |

**Total LOC**: 0. **Agent-conflict reduction**: 0.

**Verdict**: **A's stop holds.** The 6 conditionals are NOT a code-smell — they're the correct expression of multi-mode deploy semantics. Wire/fx would force build-time variance OR runtime DI overhead; current `if` blocks cost nothing and read clearly. **Fix-pattern ROI: zero.**

---

## Blocker 2 — 14 field mutations

### Enumeration (`app.X = ...` in `app/wire.go`)

| # | Line | Mutation | Phase |
|---|---|---|---|
| 1 | 105 | `app.kcManager = kcManager` | allocation |
| 2 | 122 | `app.auditStore = audit.New(alertDB)` | allocation (conditional on DB) |
| 3 | 159 | `app.hashPublisherCancel = hpCancel` | allocation (conditional) |
| 4 | 172 | `app.consentStore = audit.NewConsentStore(alertDB)` | allocation (conditional) |
| 5 | 178 | `app.consentStore = nil` | post-init reset (init-table failed) |
| 6 | 220 | `app.riskLimitsLoaded = true` | flag init |
| 7 | 228 | `app.riskLimitsLoaded = false` | flag reset (load failed) |
| 8 | 235 | `app.riskLimitsLoaded = false` | flag reset (parse failed) |
| 9 | 240 | `app.riskGuard = riskGuard` | allocation |
| 10 | 317 | `app.outboxPump = eventsourcing.NewOutboxPump(...)` | allocation (conditional) |
| 11 | 438 | `app.rateLimitReloadStop = make(chan struct{})` | allocation |
| 12 | 440 | `app.rateLimitReloadDone = rateLimitReloadDone` | allocation |
| 13 | 496 | `app.invitationCleanupCancel = invCancel` | allocation (conditional) |
| 14 | 557 | `app.paperMonitor = papertrading.NewMonitor(...)` | allocation (conditional) |
| 15 | 750 | `app.scheduler = sched` | allocation (in `initScheduler`, called from `RunServer`) |

**Phase grouping**: 11 are allocation-time set-once. 3 are flag-reset within the same phase (lines 178, 228, 235). All are init-time; App is then read-only.

### Test cascade

`grep -rln "app\.\(auditStore\|riskGuard\|consentStore\|outboxPump\|paperMonitor\|scheduler\|kcManager\|riskLimitsLoaded\|rateLimitReloadStop\|invitationCleanupCancel\|hashPublisherCancel\)" app/` → **~12 test files** mutate `app.X` directly to inject test fixtures.

### Functional-options refactor cost

Realistic LOC including ALL test cascades:
- 14 option funcs × ~5 LOC = 70 LOC option definitions
- `NewAppWithConfig` accepts `...Option` variadic + applies = ~20 LOC
- Internal staging struct or direct mutation = ~10 LOC
- 12 test files × ~10 LOC each (replace `app.X = fixture` with `app := NewApp(WithX(fixture))`) = ~120 LOC
- Edge-case migration (lines 178/228/235 — flag resets that aren't constructor injection candidates) require keeping mutable access for those 3 sites → defeats half the point
- **Total**: ~220 LOC

### "Do nothing" alternative

Leave imperative. App fields are init-time-only (post-init they're read-only). Fields are package-private (only `app/` accesses them). Test cascade exists today and is stable.

### Verdict

| Approach | LOC | Concurrency lift | Behavior change |
|---|---|---|---|
| Functional options | 220 | ~0 (App struct field list is still shared edit) | none |
| Do nothing | 0 | 0 (current state) | none |

**Verdict**: **Do-nothing wins**. 220 LOC for zero concurrency lift and zero behavior change is pure ceremony tax. The 3 flag-reset sites (178, 228, 235) actively defeat the functional-options pattern — they're conditional resets within init phase that the option funcs can't model without runtime branching. **Fix-pattern ROI: net negative.**

---

## Blocker 3 — 10 `kcManager.SetX` setters

### Enumeration with classification

| # | Line | Setter | Class | Reason |
|---|---|---|---|---|
| 1 | 150 | `SetAuditStore(app.auditStore)` | **eliminable** | auditStore allocated at line 122; no cycle |
| 2 | 297 | `SetRiskGuard(riskGuard)` | **eliminable** | riskGuard allocated independently; no cycle |
| 3 | 303 | `SetEventDispatcher(eventDispatcher)` | **mutual-recursive** | dispatcher subscribers reference kcManager state |
| 4 | 320 | `SetEventStore(eventStore)` | **mutual-recursive** | eventStore.Drain dispatches events through manager-bound handlers |
| 5 | 361 | `SetPaperEngine(paperEngine)` | **mutual-recursive** | paperEngine takes dispatcher (which references kcManager) |
| 6 | 453 | `SetBillingStore(billingStore)` | **eliminable** | billingStore is leaf storage; no cycle |
| 7 | 484 | `SetInvitationStore(invStore)` | **eliminable** | invStore is leaf storage; no cycle |
| 8 | 488 | `SetFamilyService(famSvc)` | **mutual-recursive** | famSvc constructed FROM `kcManager.UserStore() + kcManager.BillingStore()` — cycle |
| 9 | 549 | `SetMCPServer(mcpServer)` | **mutual-recursive** | mcpServer holds tool handlers that close over kcManager |
| 10 | 731 | `SetPnLService(pnlService)` | **eliminable-with-effort** | pnlService takes `kcManager.KiteClientFactory()` — cycle but indirect via Factory interface |

**Re-classification from `ebfdf3d`**: 5 truly mutual-recursive (3, 4, 5, 8, 9), 4 cleanly eliminable (1, 2, 6, 7), 1 eliminable-with-effort via interface refactor (10).

### Per-setter constructor-injection rewrite (4 cleanly eliminable)

#### Setter 1 — `SetAuditStore` (line 150)

**Current** (post-construction):
```go
// wire.go:122-150
if alertDB != nil {
    app.auditStore = audit.New(alertDB)
    if err := app.auditStore.InitTable(); err != nil { ... }
    // ... encryption setup ...
    kcManager.SetAuditStore(app.auditStore)  // line 150
}
```

**Rewrite**: Move auditStore allocation BEFORE `kc.NewWithOptions` (line 65). Pass via `kc.WithAuditStore(app.auditStore)` option (kc package already has `kc.With*` option pattern — add one more).

**LOC**: ~5 (1 new option func in kc, 1 callsite, drop 1 setter) + ~3 in `kc/manager.go` (option handler).

**Test impact**: Tests that construct manager via `kc.NewWithOptions` with a mock audit store work as-is. Tests that mutate `kcManager.SetAuditStore(fakeStore)` directly need to switch to constructor variant. ~3 test files.

**Total**: ~15 LOC including tests.

#### Setter 2 — `SetRiskGuard` (line 297)

**Current**: riskGuard allocated at line ~240 (after riskLimits load), set on manager at 297.

**Rewrite**: Same pattern — `kc.WithRiskGuard(rg)` option. Manager still needs `RiskGuard()` accessor for legacy callers (tools that read it).

**Risk**: riskGuard depends on `riskLimits` which depends on `auditStore` (for limit-load DB). If auditStore migrates first, this becomes feasible. Order matters.

**LOC**: ~5 + ~3 manager option handler + ~2 tests = ~10 LOC.

#### Setter 6 — `SetBillingStore` (line 453)

**Current**: billingStore allocated within the `if StripeSecretKey != ""` block, set on manager.

**Rewrite**: Two options:
- (a) `kc.WithBillingStore(bs)` accepting nil — manager treats nil as "no billing".
- (b) Keep imperative — billingStore presence is tied to deployment-mode (Blocker 1 cat-b).

**LOC for (a)**: ~5 + ~3 + ~2 tests = ~10 LOC.

**Caveat**: Setting billing post-construction doesn't actually break anything semantically (billing middleware is wired separately at line 462). The setter's only reader is `kcManager.BillingStore()`. **Borderline ROI** — fix is mechanical but exposes nothing the alternative doesn't.

#### Setter 7 — `SetInvitationStore` (line 484)

**Current**: invStore allocated within `if alertDB != nil` block, set on manager + then used at line 487 to construct famSvc which IS mutual-recursive.

**Rewrite**: `kc.WithInvitationStore(invStore)` — clean. Decoupling here is a prereq for tackling Setter 8 (FamilyService cycle) cleanly.

**LOC**: ~5 + ~3 + ~2 tests = ~10 LOC.

### 4 cleanly-eliminable subtotal

**Total LOC for 4 constructor rewrites**: ~45 LOC (all 4 setters) + ~15 LOC tests = **~60 LOC**.

**Concurrency lift**: minor — 4 fewer SetX calls in `wire.go` is ~4 fewer lines that any agent might collide on. Mode 2 reduction on `wire.go`: ~5%.

**Side benefit**: closes 4 of 10 `kcManager.SetX` patterns. The remaining 6 truly mutual-recursive cases stay imperative.

### 6 mutual-recursive setters — interface-segregation analysis

| # | Setter | Manager needs WHOLE? | Tractable via interface | Estimated LOC if attempted |
|---|---|---|---|---|
| 3 | `SetEventDispatcher` | NO — only `Dispatch(event)` interface | YES — `domain.Dispatcher` interface (1 method) + sync.Once for late-binding | ~80 LOC + ripple through subscribers |
| 4 | `SetEventStore` | NO — only `Append(event)` + `NextSequence()` | YES — `domain.EventAppender` interface (2 methods) | ~50 LOC + 8-10 use case touchpoints |
| 5 | `SetPaperEngine` | NO — middleware needs `Engine.Intercept(req)` | PARTIAL — paperEngine could take `domain.Dispatcher` interface in constructor; cycle relocates but doesn't disappear | ~120 LOC + middleware refactor |
| 8 | `SetFamilyService` | NO — but famSvc itself takes `kcManager.UserStore + BillingStore` — cycle is on the OTHER side | NO — would require user/billing stores to be parameter-injected to famSvc, which cascades back to the eliminable setters 1+6+7 first | gated on Setters 6+7 |
| 9 | `SetMCPServer` | NO — kcManager only needs `MCPServer()` accessor for downstream tool registration | YES — `mcp.Server` interface (1 method) | ~30 LOC + 1 callsite |
| 10 | `SetPnLService` | NO — PnL only needs `KiteClientFactory` (already an interface) | YES — pass factory at construction; pnlService doesn't need full manager | ~40 LOC |

**Tractable-with-effort total**: Setters 3, 4, 9, 10 = ~200 LOC interface plumbing + cascade tests ~150 LOC = **~350 LOC for 4 of 6 cycle-breaks**.

**Genuinely irreducible**: Setter 5 (PaperEngine via dispatcher) and Setter 8 (FamilyService — gated on prerequisite eliminable setters first).

### Total Blocker 3 fix-pattern budget

- Cleanly-eliminable 4: ~60 LOC, low risk, immediate concurrency benefit
- Tractable-with-effort 4 of 6 mutual-recursive: ~350 LOC, MED risk, ~10% Mode 2 reduction on `wire.go`
- Irreducible 2: 0 LOC

**Verdict**: **The 4 cleanly-eliminable setters ARE a real fix candidate, ~60 LOC for 4 line removals.** Concrete forward work. Concurrency benefit is small but the LOC is small too. **Fix-pattern ROI: positive but small.**

The 4 tractable-with-effort cycle-breaks are MED-cost / MED-benefit. **Defer until empirical Mode 2 conflict data on `wire.go` justifies the 350 LOC.**

---

## Blocker 6 — 11 ordered middleware layers

### Chain enumeration in current order

| Order | File:line | Middleware | Conditional |
|---|---|---|---|
| 1 | wire.go:389 | CorrelationMiddleware | always |
| 2 | wire.go:391 | TimeoutMiddleware(30s) | always |
| 3 | wire.go:393 | auditMiddleware | if `auditMiddleware != nil` |
| 4 | wire.go:410 | HookMiddleware | always |
| 5 | wire.go:413 | circuitBreaker.Middleware | always |
| 6 | wire.go:415 | riskguard.Middleware | always |
| 7 | wire.go:424 | toolRateLimiter.Middleware | always |
| 8 | wire.go:462 | billing.Middleware | if `billingStore != nil` |
| 9 | wire.go:517 | papertrading.Middleware | if `paperEngine != nil` |
| 10 | wire.go:521 | DashboardURLMiddleware | always |
| - | wire.go:526 | WithElicitation (NOT a middleware — server option) | always |
| - | wire.go:539 | WithHooks(uiHooks) (NOT a middleware — server option) | always |

**Actual middleware count: 10** (the `WithElicitation` and `WithHooks` calls are server options, not toolHandler middleware). User's framing said 13; my prior verification said 11; actual is **10**.

### Ordering dependencies

| Layer | Must-come-before | Reason |
|---|---|---|
| Correlation | Timeout, all downstream | inject ctx X-Request-ID first; cancel must propagate |
| Timeout | Audit, Hook, all downstream | cancel must reach handlers |
| Audit | Riskguard | blocked orders MUST be logged (Pass 6 documented this is intentional) |
| Hook | Circuitbreaker, Riskguard | hooks observe pre-trade state |
| Circuitbreaker | Riskguard | freeze checked before risk |
| Riskguard | Ratelimit | safety check before throttling |
| Ratelimit | Billing, Papertrading | throttle before tier-gating |
| Billing | Papertrading | tier check before paper override |
| Papertrading | DashboardURL | paper interception before response decoration |
| DashboardURL | (last) | response transformation |

**Result**: this is a STRICT TOTAL ORDERING. Every layer has a precise position. No grouping into independent stages possible.

### Builder/declarative pattern proposals

#### Option A — Priority-based registration

```go
chain := mcp.NewMiddlewareChain()
chain.Add("correlation", 100, mcp.CorrelationMiddleware())
chain.Add("timeout", 200, mcp.TimeoutMiddleware(30*time.Second))
chain.Add("audit", 300, auditMiddleware)
// ...
serverOpts = append(serverOpts, chain.Build()...)
```

**Cost**: ~80 LOC (`MiddlewareChain` type with priority-sort + nil-skip + Build) + 11 callsite changes = ~95 LOC.

**Concurrency lift**: NEAR ZERO. The shared edit point relocates from "11 lines in wire.go" to "11 priority numbers in wire.go" — same agents collide on the same file. Adding a new middleware still requires picking a priority that doesn't collide with existing ones, which IS a shared coordination artifact.

**Side effect**: priority numbers become a bikeshed concern (100, 150, 175 — what's the convention?).

#### Option B — Stage-based grouping

Define explicit stages: `pre-request`, `safety`, `dispatch`, `post-response`. Middleware registers in a stage; intra-stage order is registration order.

**Cost**: ~120 LOC (stage enum + per-stage registration + ordered iteration) + 11 callsite changes = ~135 LOC.

**Concurrency lift**: SMALL. Different agents adding middleware in different stages don't collide. Intra-stage collisions remain. Estimate: 11/wk → 6/wk = ~5% Mode 2 reduction.

**Side effect**: stage taxonomy must be documented; any new middleware that doesn't fit becomes a coordination question.

#### Option C — Single provider with imperative append (status quo)

The 11-line block in `wire.go:389-521`. No refactor.

**Cost**: 0 LOC.

**Concurrency lift**: 0 (baseline).

### Verdict

| Approach | LOC | Concurrency lift | New shared artifact |
|---|---|---|---|
| A — priority numbers | 95 | ~0 | priority space (worse) |
| B — stage grouping | 135 | ~5% Mode 2 | stage taxonomy |
| C — status quo | 0 | 0 | wire.go middleware block |

**Verdict**: **No proposal beats status quo by enough to justify the LOC.** The user's framing is correct: ordering is architectural, Wire produces values not ordered slices, and any builder relocates the shared edit without eliminating it. **Fix-pattern ROI: zero or net-negative.**

---

## Cross-blocker summary

| Blocker | Tractable LOC | Concurrency lift | ROI vs A's "stop here" |
|---|---|---|---|
| 1 — runtime conditionals × 6 | 0 | 0 | EQUAL — no fix needed |
| 2 — field mutations × 14 | 220 | ~0 | NEGATIVE (functional options is ceremony) |
| 3 — SetX × 10 (4 cleanly eliminable) | ~60 | ~5% Mode 2 | **POSITIVE (small)** |
| 3 — SetX × 10 (4 of 6 cycle-breaks via interface) | ~350 | ~10% Mode 2 | DEFER (gate on empirical conflict data) |
| 6 — middleware × 10 | 95-135 | 0-5% | NEGATIVE-to-EQUAL |

**Net verdict**:

A's "stop here" recommendation **largely holds**. The single material exception is **the 4 cleanly-eliminable SetX setters** (SetAuditStore, SetRiskGuard, SetBillingStore, SetInvitationStore) — ~60 LOC of constructor-injection rewrites is concrete, low-risk forward work. It removes 4 lines from `wire.go` post-Manager-construction phase and aligns kc package API with the existing `kc.With*` option pattern.

**Recommended single follow-up PR**: `refactor(kc): eliminate 4 post-construction SetX setters via kc.With* options` — ~60 LOC, MED risk only because of test cascade through ~3 test files, +0 score lift, +5% concurrency lift on `wire.go`.

The other 9 SetX cycle-breaks, all of Blocker 1, all of Blocker 2, and all of Blocker 6 should **stay as-is**. No structural decoupling investment beyond Phase 3a + the 4-setter cleanup is justified at current 4-agent baseline.

**Material correction to `ebfdf3d`**: that doc said "4 of 10 are eliminable as constructor args. Doesn't change Wire verdict — 6 mutual-recursion cases would still block Wire." This deeper audit confirms the 4 ARE cleanly fixable (~60 LOC) AND identifies 4 MORE (Setters 3, 4, 9, 10) tractable-with-effort via interface-segregation (~350 LOC), leaving only 2 truly irreducible (5 and 8). Wire verdict stays unchanged — even with 8 of 10 fixed, the remaining 2 mutual-recursion cases prevent Wire from delivering its predicted value. But the 4-setter cleanup is a real PR worth dispatching.

---

*Generated 2026-04-26 against HEAD `ebfdf3d`. Read-only research deliverable; no source files modified.*
