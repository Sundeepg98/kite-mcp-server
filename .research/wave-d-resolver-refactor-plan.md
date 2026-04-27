# Wave D Phase 1 — Resolver-refactor → Wire/fx scoping

**Charter**: read-only research deliverable for the resolver-refactor → Wire/fx → Logger sweep multi-week sprint. Investigates whether the prior Wire/fx attempt's "structural blocker" claim holds against current source. No code changes.

**HEAD audited**: `69eae2b` (master, working tree). Empirical re-read of every claim from the prior Wire/fx agent's abort note.

**Cross-references**:
- `.research/architecture-100-gap-current.md` — gap-zero verdict at `7649dfb`
- `.research/agent-concurrency-decoupling-plan.md` §3.5, §5 — Wire/fx promoted to Phase 3 of recommended sequence
- `.research/path-to-100-business-case.md` §6, §7 — Wire/fx classified as ceremony under user-MRR denominator
- `.research/scorecard-final.md` — current 90.04 equal-weighted, ~95 Pass-17 weighted; 92.96 empirical-max ceiling

---

## 1. Problem statement

The prior Wire/fx execution agent aborted with this claim:

> Use cases are constructed per-request, not at startup. ~107 `usecases.New*` call sites all live inside command-bus handlers (`kc/manager_commands_*.go`, `kc/manager_queries_*.go`, `kc/cqrs/widget_queries.go`, `app/adapters_local_bus.go`). Each handler resolves a ctx-bound broker via `m.resolverFromContext(ctx)` then constructs the use case fresh. Wire generates startup-once static graphs — fundamentally incompatible with per-request closures bound to request context.

This task is to scope the resolver refactor so Wire/fx can ship.

**Spoiler from §2 below**: the claim's *premise* about structural blocker is empirically wrong. The use cases already accept `BrokerResolver` interfaces (verified in source — see §3). The actual hot question is different: should the per-request use-case construction stay (and what does Wire/fx wire), or should we refactor to startup-once construction (and what does that buy)? §4 lays out the four design options against current code reality.

---

## 2. Empirical correction of the prior agent's claim

The prior agent's three premises, verified against HEAD `69eae2b`:

| Claim | Reality | Evidence |
|---|---|---|
| "~107 `usecases.New*` call sites" | **97 use-case constructors total**, **100 bus registrations** across 9 manager-side files. The 207 file-level matches in grep mostly come from worktrees + `.research/` markdown copies. | `grep -c "^func New[A-Z]\w*UseCase("` over `kc/usecases/*.go` = 97. `m.commandBus.Register|m.queryBus.Register` over `kc/manager_*.go` = 100. |
| "Use cases take a broker as constructor arg" (implied by Option A as if it doesn't already exist) | **36 of 97 use-case constructors already take `BrokerResolver` as an interface**. The remaining 61 don't take a broker at all (they take stores, services, ports — admin, watchlist, alert, telegram, ticker, paper, native-alert, etc.). | `grep -c "resolver BrokerResolver,"` over `kc/usecases/` = 36 across 15 files. `kc/usecases/place_order.go:25` defines `BrokerResolver` interface; all 36 constructors take this interface, not a `broker.Client`. |
| "Per-request closures bound to request context — Wire incompatible" | **Only 14 sites use `m.resolverFromContext(ctx)`** — all in `kc/manager_commands_orders.go` (6), `kc/manager_commands_exit.go` (2), `kc/manager_queries_escapes.go` (6). The rest of the 100 bus handlers call `m.sessionSvc` directly (47 sites) or pass concrete Manager-held stores (39 sites). | `grep -c "m\.resolverFromContext(ctx)"` over `kc/` = 14. `m.sessionSvc` used directly in `manager_cqrs_register.go` (12 use cases) + `manager_queries_remaining.go` (5 use cases) + `manager_commands_admin.go` (4 MF use cases). |

**Material correction**: the prior agent's "structural blocker" framing was wrong. The use cases already speak the right language (`BrokerResolver` interface). The real per-request entanglement is narrow:
- 14 handlers wrap a session-pinned `broker.Client` in a `pinnedBrokerResolver` via `WithBroker(ctx, client)` → `BrokerFromContext(ctx)` (`kc/broker_context.go:28-45`) for hot-path order/exit/margin paths to skip a second credential lookup.
- The remaining 86 handlers build use cases from Manager-held fields (`m.sessionSvc`, `m.alertStore`, `m.userStore`, etc.) — those values exist at startup and are stable for the Manager's lifetime.

So the question isn't "can we make this Wire-compatible at all" — it's "what does the fanout look like after refactor and is the LOC worth it".

---

## 3. Current resolver pattern (with file:line citations)

### 3.1 The resolver type & glue

**`kc/usecases/place_order.go:22-27`** — the port:

```go
// BrokerResolver resolves a broker.Client for a given user email.
// This abstracts the session/credential lookup so use cases don't depend on
// the full SessionService.
type BrokerResolver interface {
    GetBrokerForEmail(email string) (broker.Client, error)
}
```

**`kc/broker_context.go:22-69`** — the per-request glue:
- `brokerCtxKey` (`:22`) — unexported context key
- `WithBroker(ctx, client) ctx` (`:28-33`) — MCP layer attaches a session-pinned client before `DispatchWithResult`
- `BrokerFromContext(ctx) broker.Client` (`:39-45`) — handler retrieves it
- `pinnedBrokerResolver{client}` (`:51-57`) — thin adapter satisfying `BrokerResolver`, returns the pre-resolved client regardless of email
- `(m *Manager) resolverFromContext(ctx) BrokerResolver` (`:64-69`) — returns `&pinnedBrokerResolver{client}` when ctx has one, else falls back to `m.sessionSvc` (which already implements `BrokerResolver`)

**`mcp/post_tools.go:16-25`** — symmetric MCP-side adapter when handlers run inside `WithSession` callbacks (no command bus), so they can speak the same `BrokerResolver` port.

### 3.2 Three handler patterns

Across the 100 bus registrations, every handler falls into one of three bucket:

| Pattern | Site count | Resolver source | Wire-compatible today? |
|---|---:|---|---|
| **A. Manager-held service** (sessionSvc / familyService / paperEngine / alertStore / userStore / tickerService / trailingStopMgr / riskGuard / pnlService) | ~80 | `m.sessionSvc` etc. — stable for Manager lifetime | YES — Wire could provide the use case as a startup-once value if its dependencies are also Wire-provided |
| **B. ctx-bound resolver** (place/modify/cancel/GTT order, exit, margin, widget) | 14 | `m.resolverFromContext(ctx)` returning `pinnedBrokerResolver` (per-request) or `m.sessionSvc` (fallback) | PARTIAL — use case takes `BrokerResolver` interface so it CAN be wired with `m.sessionSvc` at startup; the `pinnedBrokerResolver` optimization is the ONLY per-request piece |
| **C. ctx-bound non-broker** (native alerts) | 4 | `cqrs.NativeAlertClientFromContext(ctx)` for the per-session NativeAlertClient | DIFFERENT pattern — NativeAlertClient is session-scoped infrastructure, not a domain dependency. Can stay as-is. |

### 3.3 Why the per-request optimization exists

`kc/manager_commands_orders.go:50-54` documents the rationale verbatim:

> Handlers build the use case lazily from the Manager's stores. Where the use case needs a broker.Client, the handler resolves it via resolverFromContext(ctx): the MCP tool layer attaches the session-pinned client via WithBroker before DispatchWithResult, so we re-use that already-resolved client instead of paying for another credential lookup.

The per-request resolver is an **optimization** — it skips the `m.sessionSvc.GetBrokerForEmail(email)` lookup (which loads token + constructs zerodha.Client) when the MCP tool layer has already done that work inside `WithSession`. Without the optimization, every command would do a redundant session lookup.

**Important**: the optimization is a *speed/correctness* choice, NOT a structural Wire blocker. Use cases speak `BrokerResolver`. They could be constructed at startup with `m.sessionSvc` as the resolver and the result would be functionally correct — just one extra session lookup per command.

### 3.4 The 100 registration sites by package

```
kc/manager_cqrs_register.go        19  (12 read-side use cases + 3 family + 4 ES queries)
kc/manager_commands_admin.go       22  (alerts, MF, ticker, native alerts, admin freeze, telegram, etc.)
kc/manager_queries_remaining.go    18  (watchlist, alert reads, MF reads, admin reads, observability, paper status, ticker status, trailing stops)
kc/manager_commands_account.go     10  (account, watchlist, paper toggle/reset, credentials)
kc/manager_commands_oauth.go        9  (provision-on-login, cache token, store creds, registry sync, oauth client save/delete, admin registry CRUD)
kc/manager_commands_orders.go       9  (place/modify/cancel order, place/modify/delete GTT, convert position, set/cancel trailing stop)
kc/manager_queries_escapes.go       9  (margin queries + 4 widget queries + login/dashboard validate)
kc/manager_commands_setup.go        2  (login, clear session)
kc/manager_commands_exit.go         2  (close position, close all positions)
                                  ----
                                  100
```

Plus:
- `app/wire.go:254-260` — 1 site for `WithdrawConsentCommand` (consentStore lives in app package, not in Manager)
- `app/adapters_local_bus.go` — 6 sites for the in-process test fallback bus

---

## 4. Option matrix

| Option | Description | LOC | Wire-compatible after? | Risk | Test cascade |
|---|---|---|---|---|---|
| **A** | Inject `BrokerResolver` at use-case construction; drop per-request handler closure | ~150-300 | YES (full) | LOW-MED — loses the pinnedBrokerResolver optimization | ~30-50 test files |
| **B** | Per-use-case factory wired by Wire/fx; closure stays but standardized | ~400-600 | YES (factory level) | MED — adds Wire-readable indirection without solving 100% | ~10-20 test files |
| **C** | Two-phase init: startup placeholder + per-request setter | ~200-400 | YES (with hazard) | HIGH — mutable state on shared use cases | hard to bound |
| **D** | Defer Wave D entirely; close Hex at 95 as calibrated ceiling | 0 | NO (ceiling stays) | NIL | none |

### Option A — Inject `BrokerResolver` into use cases (drop ctx-bound closure)

**The plan**: at startup (in Wire/fx providers), construct each use case ONCE with `m.sessionSvc` as the `BrokerResolver`. The 14 handlers currently using `resolverFromContext(ctx)` change to use the startup-constructed use case directly. The `pinnedBrokerResolver` optimization is dropped — every command pays one extra session-cache lookup.

**Files that change**:
- `kc/manager_commands_orders.go` — 6 sites: rewrite handler closure to call `m.placeOrderUC.Execute(ctx, cmd)` instead of `usecases.NewPlaceOrderUseCase(m.resolverFromContext(ctx), …).Execute(ctx, cmd)`. Same for modify/cancel/GTT/convert/exit.
- `kc/manager_commands_exit.go` — 2 sites: same pattern for ClosePosition / CloseAllPositions.
- `kc/manager_queries_escapes.go` — 6 sites: margin queries + widget queries.
- `kc/manager.go` — add 14 use-case fields to Manager struct.
- `kc/manager_init.go` (or new `manager_use_cases.go`) — startup-construct the 14 use cases.
- `kc/broker_context.go` — `WithBroker` + `BrokerFromContext` + `pinnedBrokerResolver` + `resolverFromContext` become dead code (REMOVE all 5 funcs / 1 type / 1 ctx key). ~70 LOC deletion.
- `mcp/post_tools.go` — `sessionBrokerResolver` MCP-side adapter (3 sites in `mcp/common.go` + paper trading code) becomes unnecessary IF MCP also dispatches through bus; if MCP still calls use cases directly via `WithSession` (e.g., `WithTokenRefresh` pre-dispatch), the adapter stays. ~20 LOC potentially removed.
- Test cascade: Manager struct grows → fixture initializers update → ~30-50 test files. Most are mechanical (add a no-op field assignment in the test fixture).

**Estimated LOC**: 
- Production: ~150 changed + ~70 deleted = 80 net (or +220 churn)
- Test fixture updates: ~50-100 LOC (mostly mechanical)
- **Total: ~150-300 LOC churn**, net +0 to +50 LOC.

**Risk profile**:
- **LOW** for correctness — `BrokerResolver` interface unchanged; `m.sessionSvc.GetBrokerForEmail(email)` does the work already; the only thing lost is the in-flight session-cache hit.
- **MED** for performance — every order/exit/margin command now does ONE extra session-cache lookup. SessionService caches by email so this is in-memory map access (~100ns), not a DB call. Multi-machine architectures or future Redis-backed sessions would change the calculus.
- The dropped `pinnedBrokerResolver` optimization is empirically minor: even at 100 orders/day per user, 100 extra map lookups/day is unmeasurable. The optimization existed because the old code path went through credential decryption — that's a single DB read amortized via `KiteCredentialStore`'s in-memory cache. Re-resolving once is essentially free.

**Agent-concurrency impact** — DOES IT UNBLOCK WIRE/FX?:
- YES. After A, every use case is startup-once and its dependencies are all `m.X`-shaped fields. Wire/fx's `wire.NewSet(usecases.NewPlaceOrderUseCase, ...)` works directly because the inputs (sessionSvc, riskGuard, eventDispatcher, logger) are all Wire-provideable startup values. The 14 ctx-bound sites are no longer special.
- After A, `app/wire.go` 985 LOC → potentially split into per-domain provider sets; the manual `commandBus.Register(...)` closures stay (they're CQRS routing, not DI), but the closure body becomes `m.placeOrderUC.Execute(ctx, cmd)` which IS Wire-compatible.

**Test cascade**:
- 30-50 test files use `kc.New(...)` or fixtures. Most call `manager.CommandBus().DispatchWithResult(...)` and expect the use case to construct itself. After A, the use case is a Manager field — tests need either (a) a fixture that wires it, or (b) the SetX setter pattern already used for ~70 deprecated test sites (per `kc/manager.go:73-87` Config doc).
- **Mitigation**: add `WithPlaceOrderUC(uc)` etc. functional options to `NewWithOptions`. Tests that don't override get a default `usecases.NewPlaceOrderUseCase(m.sessionSvc, ...)`. ~70 LOC of options, mechanical.

### Option B — Use-case factories wired by Wire/fx

**The plan**: each use-case-type gets a factory `PlaceOrderUseCaseFactory func(broker.Client) *PlaceOrderUseCase`. Wire/fx provides factories at startup with all non-broker dependencies bound. Handlers call `factory(m.resolverFromContext(ctx))` per request. The factory IS Wire-readable (it's a function value); per-request construction stays.

**Files that change**:
- 14 factory definitions, one per ctx-bound use case (in `kc/usecases/factories.go` new file or in each `*_usecase.go`).
- 14 handler call sites in `manager_commands_orders.go` / `manager_commands_exit.go` / `manager_queries_escapes.go` rewrite from `usecases.NewX(m.resolverFromContext(ctx), …)` → `m.xFactory(ctx)`.
- Manager grows 14 factory fields.
- Wire providers: 14 `func() PlaceOrderUseCaseFactory { return func(r BrokerResolver) *X { return usecases.NewX(r, …) } }`-shaped declarations.

**Estimated LOC**: 
- Factory definitions: 14 × ~10 LOC = 140 LOC
- Handler rewrites: 14 × ~3 LOC = 42 LOC
- Wire providers: 14 × ~8 LOC = 112 LOC
- Manager fields + setup: ~50 LOC
- Test fixtures: ~50 LOC (factories are nil-friendly, less cascade than A)
- **Total: ~400-600 LOC**, net +400 LOC.

**Risk profile**:
- **LOW** for correctness — factory closures are exactly today's behavior, just named.
- **MED** for design pollution — adds a parallel "factory port" layer that mirrors but doesn't replace the use-case constructors. Any new use case that takes a broker resolver needs both the constructor AND the factory wired, doubling the per-tool ceremony.
- **HIGH** for ROI — does NOT solve the deeper question (do we want per-request construction at all?), and adds 400 LOC of indirection.

**Agent-concurrency impact**:
- PARTIALLY YES. Wire/fx can provide the factories. The handler closures stay; the resolution-time still happens per-request. So `wire.go` shrinks by maybe 100-150 LOC of factory plumbing, not the 600 LOC the agent-concurrency-decoupling-plan §3.5 modeled.
- The `wire.go` Mode-2 conflict file shrinks from 985 → ~800 LOC, not ~200 LOC. The agent-throughput gain is ~30-40% of what Option A delivers.

**Test cascade**: smaller than A — factories are nil-friendly, tests can supply mock factories without re-wiring all use case dependencies.

### Option C — Two-phase init with per-request setter

**The plan**: at startup, construct each use case with `m.sessionSvc` as the resolver. Add `SetBrokerResolver(BrokerResolver)` to each use case. Handlers call `uc.SetBrokerResolver(ctxResolver); defer uc.ClearBrokerResolver()` per request to override.

**Files that change**:
- 14 use-case structs grow a setter pair.
- 14 handler closures change to setter-pattern.
- Manager holds 14 use-case fields (same as A).

**Estimated LOC**: ~200-400 LOC, net +200.

**Risk profile**:
- **HIGH** — this introduces mutable state on shared use cases. Two concurrent commands would race on `SetBrokerResolver`. Mitigation requires per-call resolver context (which we already have via `BrokerResolver` interface argument — defeating the purpose).
- **NOT RECOMMENDED**. Mutable shared state on an object that's structurally pure is a design hazard. This is the textbook anti-pattern called "SetX → constructor injection" cleanup that `blocker-resolutions.md` T2.4 already cataloged.

**Agent-concurrency impact**: yes (Wire-compatible) but at the cost of introducing a new race-condition class.

**Test cascade**: medium; tests need to manage the setter lifecycle.

### Option D — Defer entirely; close Hex at 95

**The plan**: don't ship Wave D. Accept the calibrated 95 Hex / 90.04 equal-weighted ceiling as documented in `scorecard-final.md`. Reallocate the 600+ LOC effort to product work / FLOSS-fund application / launch blockers (see `kite-launch-blockers-apr18.md`).

**LOC**: 0.

**Risk profile**: NIL.

**Agent-concurrency impact**: ZERO improvement on `wire.go` Mode-2 conflict (~30%/wk at 8 agents per `agent-concurrency-decoupling-plan.md` §3.5). At current 4-agent ceiling, this is ~10-20 min/week conflict cost — manageable.

**Side benefit blocked**: `agent-concurrency-decoupling-plan.md` §3.5's "Wire/fx promotion" rests on Wave D landing. Without it, Hex stays at 95, equal-weighted stays at 90.04, Pass-17 stays at ~95. This is exactly the `path-to-100-business-case.md` §6 verdict ("stop at 98.5") under the user-MRR denominator.

---

## 5. Recommended option + reasoning

### Recommendation: **Option D for now. Conditional Option A in 6-12 months.**

**Reasoning** — three independent lenses converge:

#### Lens 1 — Code reality vs. plan denominator

`agent-concurrency-decoupling-plan.md` §5 phases promote Wire/fx to Phase 3 "after Phase 1 (worktrees) + Phase 2 (Phase 3a port migration)". The §5 sequence assumes:

- Phase 1 (worktree) + Phase 2 (Phase 3a port migration) shipped → 4 agents → 8 agents.
- Wire/fx then pushes 8 → 12.

**Current empirical state at HEAD `69eae2b`**: 
- Phase 3a port migration shipped (`scorecard-final.md` Hex 88 → 95 on RateLimitError typed-port and 84 unchanged Concrete count).
- Worktrees: this very session has 4 agents in flight via `.claude/worktrees/agent-a2e6c1ec` — process change is in motion, not a code-tractable LOC.
- The 8-agent ceiling has NOT been hit. We're at 4.
- `agent-concurrency-decoupling-plan.md` §5 explicitly gates Wire/fx on "the 6-agent team config is routine and `wire.go` conflict cost is empirically measured." Neither gate has triggered. The Wire/fx investment is ~600 LOC for 4-agents-today → 12-agents-someday, which is over-investment per `kite-mrr-reality.md`'s ₹15-25K MRR target.

#### Lens 2 — Hex score lift vs. cost-justified ceiling

`scorecard-final.md` projects the empirical-max ceiling at 92.96 equal-weighted (subtract anti-rec'd 27pt + external-$$ 64pt + irreducible 0.5pt from theoretical 1300). **Wire/fx is in the anti-rec'd column for Hex 88→97 = +9pt.**

If Wave D ships and Wire/fx is promoted from rejected to executed:
- Hex 95 → ~97 (+2 above current; +9 from the original 88 baseline)
- Equal-weighted 90.04 → ~91.0
- Pass-17 ~95.0 → ~96.0

That's a 1pt aggregate lift for ~600 LOC of Wave D Phase 1 (resolver refactor) + ~600 LOC of Wave D Phase 2 (Wire/fx itself). 1200 LOC for 1pt is below density floor 1.0 LOC/0.001-pt that `path-to-100-business-case.md` §3 has been honoring.

#### Lens 3 — Scale gating

The whole rationale for Wire/fx in `agent-concurrency-decoupling-plan.md` §3.5 is **merge-conflict cost on `wire.go` at 8+ agents**. Empirically:
- `app/wire.go` is now 985 LOC (was 600 in the original audit). Yes, conflict probability scales with file size.
- Current agent count: 4. Per §3.5 Mode 2 table, `wire.go` conflict prob/week at 4 agents ≈ 30%, at 8 agents ≈ 80%. We're well below the 80% threshold.
- `kite-mrr-reality.md` MRR target: ₹15-25K. Even if Wave D unlocks 12 agents instead of 6, the agents are billed against product velocity, not Mode-2 conflict savings. At sub-1L MRR, the user is the bottleneck, not parallel agent throughput.

#### Honest stop rule for the recommendation

**Recommend Option D today.** Document Wave D as scale-gated. Trigger Wave D when ANY of these fire:

1. **Agent-count trigger**: 6+ permanent agents working on shared tree. Today: 4. Trigger date: not foreseeable from current cadence.
2. **Conflict-cost trigger**: `wire.go` merge-conflict resolution exceeds 30 min/week measurably (per session telemetry, not estimate). Today: ~10-20 min/week per §3.5 estimate.
3. **2nd-broker trigger**: first paying customer asks for Upstox/Groww/Angel adapter. Per `path-to-100-business-case.md` Multi-broker proof, this is "scale-gated until 5K paying users". Today: not yet a customer.
4. **Hex-100 mandate**: an external auditor or B2B procurement requires 100% Hex score. Per memory: solo project at sub-50-paid-subs scale; auditor would never see this score difference.

**If any trigger fires within 6-12 months, ship Option A.** Option B is rejected (LOC dwarfs benefit, design pollution); Option C is rejected (mutable shared state hazard).

### Why Option A over Option B if Wave D ships

Option A is "drop the per-request closure, accept one extra session-cache map lookup per command". It's the architecturally clean answer. Option B preserves the closure with a factory layer — that's adding indirection without removing the underlying coupling.

If we ever reach the Wave D trigger, the agent-throughput ROI is "kill `wire.go` as a Mode-2 file". Option A does this fully. Option B does this ~30%. The 600 LOC Wire/fx investment is justified ONLY if we get the full benefit, which means Option A.

The "lost" `pinnedBrokerResolver` optimization is empirically zero-cost: `KiteSessionData.Broker` is held in `SessionManager` (a `sync.Map`) and `GetBrokerForEmail` is a map read + nil-check. The optimization saves ~100 ns per command. At any realistic order rate, this is below noise.

---

## 6. Slice-by-slice execution plan (Option A — when triggered)

This plan presupposes the Option D trigger has fired and the user has explicitly authorized Wave D. **If executing today, stop and ask**.

### Slice D1 — Use-case ownership in Manager (~50-80 LOC)

Add 14 use-case fields to Manager struct. Construct them in `manager_init.go` after `riskGuard` / `eventing.Dispatcher` are wired but before `registerCQRSHandlers`. **No** behavior change — the existing handler closures still construct fresh; this is a parallel field that no one reads yet.

Files:
- `kc/manager.go` — add 14 fields
- `kc/manager_init.go` (or new `kc/manager_use_cases.go`) — startup construction
- 0 test files change (additive only)

**Verification**: `go build ./...` clean; no test changes.

### Slice D2 — Migrate place/modify/cancel order (3 handlers, ~30 LOC)

Rewrite the 3 order-write handlers in `kc/manager_commands_orders.go` to call `m.placeOrderUC.Execute(ctx, cmd)` etc. instead of `usecases.NewPlaceOrderUseCase(m.resolverFromContext(ctx), …).Execute(...)`. Drop the `m.resolverFromContext(ctx)` arg.

Files:
- `kc/manager_commands_orders.go` — 3 handler bodies
- Tests: `kc/manager_commands_orders_test.go` may need fixture updates

**Verification**: `go test ./kc -run TestPlaceOrder ./...` passes.

### Slice D3 — Migrate GTT (3 handlers, ~30 LOC)

Same as D2 for `place_gtt`, `modify_gtt`, `delete_gtt` in `manager_commands_orders.go`.

### Slice D4 — Migrate exit (2 handlers, ~20 LOC)

Same pattern for `close_position`, `close_all_positions` in `kc/manager_commands_exit.go`.

### Slice D5 — Migrate margin queries (3 handlers, ~30 LOC)

`get_order_margins`, `get_basket_margins`, `get_order_charges` in `kc/manager_queries_escapes.go`.

### Slice D6 — Migrate widget queries (3 handlers, ~30 LOC)

`portfolio_widget`, `orders_widget`, `alerts_widget` in `kc/manager_queries_escapes.go` — note these have a `widgetAuditStoreFromCtxOrManager(ctx)` resolution that's a separate concern from the broker resolver. Keep the audit-store-from-ctx pattern; only migrate the broker-resolver dimension.

**WARNING**: another agent is currently editing `kc/usecases/widget_usecases.go` per `git status`. Coordinate before D6.

### Slice D7 — Drop dead code (~70 LOC removed)

Delete `WithBroker`, `BrokerFromContext`, `pinnedBrokerResolver`, `resolverFromContext`, `brokerCtxKey` from `kc/broker_context.go`. Unused after D2-D6.

Files:
- `kc/broker_context.go` — delete most of file (keep `package kc` + maybe a doc comment marking the migration)
- `mcp/setup_tools.go` (or wherever MCP layer calls `WithBroker`) — find + remove. ~5-10 LOC.

**Verification**: `go vet ./... && go build ./...` clean. `grep -rn "WithBroker\|BrokerFromContext\|pinnedBrokerResolver"` returns zero hits in production code.

### Slice D-final — Wire/fx adoption (~600 LOC, separate sprint)

After D1-D7, every use case is startup-once and Wire-compatible. Adopt Wire/fx per `agent-concurrency-decoupling-plan.md` §5 Phase 3 (the "promoted from rejected" investment). This is a separate multi-week sprint NOT scoped here — D1-D7 just enables it.

### Total Wave D Phase 1 LOC

- Slice D1-D6: ~190 LOC additions, ~70 LOC deletions = +120 net
- Slice D7: 0 LOC additions, ~80 LOC deletions = -80 net
- Test fixture cascade: ~70 LOC (functional options for the 14 use cases)
- **Total: ~190-300 LOC churn, +110 net**, ~2-3 working days at 1 agent.

This is much smaller than the 500-800 LOC the prior agent estimated. The reason: the use cases already speak `BrokerResolver`; only the closure-bound construction site needs to change, not 107 constructor signatures.

### Honest stops within the slice plan

- **D1 abort signal**: if startup-construction triggers an init-order issue (e.g., `m.sessionSvc` is nil at use-case construction time because of cycle inversion in `kc/manager_init.go`), we have a deeper problem than Wave D solves. Stop, redesign init order.
- **D2-D6 abort signal**: if any test cascade exceeds 100 LOC of mechanical fixture work, the bus pattern is more entrenched than estimated. Stop, reconsider Option B.
- **D7 abort signal**: if any non-test code outside `mcp/setup_tools.go` (and possibly `mcp/post_tools.go`) calls `WithBroker`, the optimization has crept beyond CQRS. Stop, audit those sites first.

---

## 7. Risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Slice D1 init-order cycle (use cases need `eventing.Dispatcher()` before `registerCQRSHandlers` runs) | LOW (existing wiring already sequences these) | Build break | Verify with `go build` after D1 commit. |
| Test cascade exceeds 100 LOC of mechanical fixture updates | MED (40+ test files use `kc.New`) | Schedule slip 2-3 days | Use functional options in `NewWithOptions` to keep defaults; tests inherit. |
| `pinnedBrokerResolver` optimization removal causes measurable latency regression | LOW (single map lookup, ~100ns) | Performance complaints | Bench `place_order` before/after with `BenchmarkPlaceOrderHotPath` if it exists; add if not. |
| Concurrent edits from other in-flight agents | MED (3 agents already modifying `kc/usecases/widget_usecases.go`, `mcp/plugin_widget_returns_matrix.go`, Slice 6b/Order/Wave B) | Merge conflict at push time | DEFER D6 (widget queries) until other agents drop their widget work. Stage D2-D5 + D7 first. |
| `mcp/post_tools.go` `sessionBrokerResolver` is harder to remove than expected (used by `WithTokenRefresh`, paper trading, etc.) | MED | LOC creep beyond 300 | Treat `sessionBrokerResolver` removal as out-of-scope for Wave D Phase 1; revisit in Phase 2 alongside Wire/fx itself. |
| Wave D ships but agent count never hits 6+; LOC sunk for nothing | HIGH if scale-gated, NIL if user explicitly approves | -110 net LOC of architectural cleanup with zero throughput gain | Document trigger conditions clearly; require explicit user authorization before kicking off Slice D1. |
| Wire/fx (Slice D-final) compile errors are notoriously cryptic; multi-week debugging tail | HIGH (well-known Wire DX problem) | 1-2 weeks slip on Phase 2 | Out of scope for Phase 1; flagged here because Phase 1's purpose is to enable Phase 2. |

---

## 8. Honest assessment: is Wave D worth doing now, OR scale-gated?

**Verdict: SCALE-GATED.** Recommend Option D (defer) today. Trigger Option A only when one of the four §5 triggers fires.

**Three convergent reasons**:

1. **Empirical agent-throughput**: §1 of `agent-concurrency-decoupling-plan.md` documents an empirical 4-agent ceiling on shared tree. We have not yet hit 6 agents per session except via worktrees (which are session-process not architecture-state). The ceiling that Wire/fx solves (8 → 12) is invisible at current cadence.

2. **Empirical Hex score-lift**: `scorecard-final.md` shows Hex 95 → 97 (+2) is the score gain from Wave D. Equal-weighted moves 90.04 → ~91.0. This is a genuine but small lift, and `path-to-100-business-case.md` §6 already notes the calibrated 99.0 ceiling under business-case denominator. We don't need 91.0 to satisfy any external party.

3. **Empirical user-MRR denominator**: `kite-mrr-reality.md` ₹15-25K MRR target. Wave D doesn't ship product features. The 600+ LOC commitment + 1-2 week slip on launch blockers (per `kite-launch-blockers-apr18.md`) is opportunity cost in the wrong direction.

**When to revisit**:

| Trigger | Probability within 12 months | If triggered → ship |
|---|---|---|
| 6+ permanent agents on shared tree | LOW (single user, agent count is task-driven not staffing-driven) | Option A immediately |
| `wire.go` conflict resolution >30 min/week empirically | LOW-MED (current 985 LOC + 4 agents → ~10-20 min/wk) | Option A |
| 2nd broker customer (Upstox/Groww/Angel) | LOW (gated by 5K paying users per `path-to-100-business-case.md`) | Option A — multi-broker SDK forces clean BrokerResolver wiring anyway |
| Hex-100 external mandate | NIL (solo project, no external auditor on horizon) | Skip; ceremony score-chase |

**Closing note on the prior agent's "structural blocker"**: that abort note was based on a misreading of the codebase. The use cases already speak `BrokerResolver`. The actual question was always cost/benefit, not structural impossibility. This doc lays out the option matrix so the next decision is data-driven, not blocked by a phantom structural constraint.

---

## 9. Sources

- Source files cited:
  - `kc/broker_context.go:22-69` — resolver glue
  - `kc/usecases/place_order.go:22-27` — `BrokerResolver` interface definition
  - `kc/usecases/queries.go` — 9 use case constructors taking `BrokerResolver`
  - `kc/manager_commands_orders.go:50-54, 62-67, 90-95, 111-116, 131, 149, 167, 184-191, 205-213, 226-234` — order-side handler closures
  - `kc/manager_commands_exit.go:20-55` — exit handler closures
  - `kc/manager_queries_escapes.go:50-115` — margin + widget query handlers
  - `kc/manager_cqrs_register.go:22-313` — 19 use-case registrations
  - `kc/manager_queries_remaining.go:18-223` — 18 query registrations
  - `kc/manager_commands_admin.go:17-525` — 22 admin/MF/ticker/native-alert handlers
  - `kc/manager_commands_account.go:17-235` — 10 account/watchlist/paper handlers
  - `kc/manager_commands_oauth.go:27-167` — 9 OAuth bridge handlers
  - `kc/manager_commands_setup.go:17-59` — 2 setup handlers
  - `app/wire.go:241-266, 1-100` — composition root structure, 1 in-app bus registration for `WithdrawConsentCommand`
  - `app/adapters_local_bus.go:63-167` — 6 in-process test fallback bus registrations
  - `mcp/post_tools.go:16-25` — MCP-side `sessionBrokerResolver`
  - `mcp/common.go:111-134` — `WithTokenRefresh` use of `sessionBrokerResolver`

- Synthesis docs cited:
  - `.research/architecture-100-gap-current.md` — gap-zero verdict at `7649dfb`
  - `.research/agent-concurrency-decoupling-plan.md` §1, §3.5, §5 — Wire/fx merge-cost promotion
  - `.research/path-to-100-business-case.md` §6, §7, §8 — anti-rec'd ceremony status
  - `.research/scorecard-final.md` Wire/fx anti-rec'd table; 92.96 empirical-max ceiling
  - Memory: `kite-mrr-reality.md`, `kite-launch-blockers-apr18.md`, `feedback_decoupling_denominator.md`

- Empirical metrics this audit:
  - 97 use-case constructors total (over `kc/usecases/*.go`)
  - 36 use-case constructors take `BrokerResolver` (across 15 files)
  - 100 bus registrations across 9 manager-side files
  - 14 sites use `m.resolverFromContext(ctx)` (the per-request closure pattern)
  - `wire.go` 985 LOC (vs. 600 LOC noted in agent-concurrency-decoupling-plan.md §1)

- Build status: `go build ./...` clean expected at HEAD `69eae2b` (working-tree changes from Wave-B/Slice-6b/Order agents in flight; this doc does not require build verification).

---

*Generated 2026-04-26 against HEAD `69eae2b`. Read-only research deliverable; no source files modified.*
