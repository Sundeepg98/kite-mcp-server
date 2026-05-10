# kc/manager Decomposition — Phase 2 Survey + Design

Phase 2 dispatch (post Path A.27 closure). **Research-only**. Continuation
of prior session's PR 6.15 work (manager.go 413 → 140 LOC).

State at survey: master HEAD `b21ad3e` = production v253 LIVE with 28
algo2go modules. Time budget: ~1.5h remaining of Phase 1+2 allotment.

---

## 1. Empirical state of kc/ (as of HEAD b21ad3e)

### 1.1 manager_*.go production files

| File | LOC | Concern |
|---|---|---|
| `manager.go` | 140 | Constructors only (post PR 6.15) |
| `manager_struct.go` | 186 | Struct field declarations + constants |
| `manager_init.go` | 530 | 16-phase wiring helpers |
| `manager_interfaces.go` | 266 | ISP store-provider interfaces |
| `manager_accessors.go` | 113 | 11 getter methods |
| `manager_lifecycle.go` | 124 | Start/Stop |
| `manager_use_cases.go` | 170 | initOrderUseCases (13 use-case fields) |
| `manager_cqrs_register.go` | 314 | CQRS handler registration |
| `manager_reconstitution.go` | 215 | Event-sourcing replay |
| `manager_orders_fallback.go` | 91 | Fallback order strategy |
| `manager_queries_remaining.go` | 223 | Read-side queries |
| `manager_queries_escapes.go` | 182 | Escape-hatch queries |
| `manager_commands_account.go` | 272 | Account-tier commands |
| `manager_commands_admin.go` | 533 | Admin RBAC commands (largest) |
| `manager_commands_oauth.go` | 311 | OAuth flow commands |
| `manager_commands_orders.go` | 208 | Order commands |
| `manager_commands_setup.go` | 59 | Setup commands |
| `manager_commands_exit.go` | 43 | Exit commands |
| **Total production** | **~3,980 LOC** | 18 files |

Plus 16 _test.go files = 11,564 LOC total.

### 1.2 Already-extracted services (post PR 6.15)

| File | LOC | Pattern |
|---|---|---|
| `session_service.go` | 566 | Standalone (no `m *Manager` back-pointer in core) |
| `credential_service.go` | 263 | Standalone |
| `store_registry.go` | 220 | Facade with `m *Manager` back-pointer |
| `broker_services.go` | 133 | Facade with back-pointer |
| `session_lifecycle_service.go` | 120 | Facade with back-pointer |
| `eventing_service.go` | 113 | Facade with back-pointer |
| `order_service.go` | 103 | Standalone |
| `family_service.go` | 102 | Standalone |
| `scheduling_service.go` | 99 | Facade with back-pointer + mutates Manager state |
| `portfolio_service.go` | 89 | Standalone |
| `alert_service.go` | 88 | Standalone |
| **Total services** | **~2,200 LOC** | 11 files |

**Decomposition is mature**. Services split: standalone (8) vs back-pointer
facades (3). The facades are intermediate — first split was "group concerns
into named units"; next split is "make each unit independent of Manager".

### 1.3 Manager struct empirical shape

70+ fields organized:

| Category | Count | Examples |
|---|---|---|
| Identity / config | 7 | apiKey, apiSecret, accessToken, Logger, metrics, appMode, etc. |
| Templates | 1 | `templates map[string]*template.Template` |
| Focused services | 7 | CredentialSvc, SessionSvc, ManagedSessionSvc, PortfolioSvc, OrderSvc, AlertSvc, FamilyService |
| Decomposed facades | 5 | stores, eventing, brokers, scheduling, sessionLifecycle |
| Persistence stores | 11 | tokenStore, credentialStore, alertStore, watchlistStore, userStore, registryStore, telegramNotifier, alertDB, ownsAlertDB, encryptionKey, auditStore |
| Optional infra | 7 | riskGuard, paperEngine, billingStore, invitationStore, eventDispatcher, eventStore, projector |
| Auth / signing | 3 | sessionManager, sessionSigner, kiteClientFactory |
| Service handles | 3 | Instruments, alertEvaluator, trailingStopMgr, tickerService |
| MCP coupling | 1 | mcpServer (any — circular import dodge) |
| CQRS buses | 2 | commandBus, queryBus |
| Wave D Slice D2-D6 use cases | 13 | placeOrderUC, modifyOrderUC, cancelOrderUC, place/modify/deleteGTTUC, closePosition/closeAllPositionsUC, get{Order,Basket,OrderCharges}MarginsUC, getPortfolio/AlertsForWidgetUC |

### 1.4 Method count + categories

47 methods on `*kc.Manager`:

| Category | Count | Status |
|---|---|---|
| Init helpers (`init*`) | 16 | Phase-ordered constructors; mostly mutate Manager fields |
| Command registration (`register*Commands`) | 10 | Bus-handler wiring |
| Accessors (getters/setters) | 11 | `CommandBus()`, `QueryBus()`, `SessionManager()`, etc. |
| Lifecycle | 4 | initializeTemplates, initializeSessionSigner, Shutdown, etc. |
| Internal helpers | 6 | projectionOrdersForEmail, widgetAuditStoreFromCtxOrManager, etc. |

### 1.5 Reverse-dep breadth

78 production files outside kc/ reach `*kc.Manager`:
- `app/`: 5 files (adapters, app, http, providers/manager, wire)
- `app/providers/`: indirect via providers/manager.go
- `mcp/`: 73 files (admin, alerts, analytics, common, helpers, paper,
  portfolio, plugin_widgets, trade, watchlist, tax, tools_*)

This is the kc-Manager-as-MCP-context surface. Most reach via
`*kc.Manager` for either:
1. Service handles (`m.SessionSvc.Foo()`) — clean, narrow access
2. Direct field access (`m.tokenStore.Get(email)`) — tight coupling
3. Bus access (`m.CommandBus()`, `m.QueryBus()`) — clean, narrow

### 1.6 Existing ISP work (manager_interfaces.go)

11+ focused store-provider interfaces already declared:
- TokenStoreProvider, CredentialStoreProvider, TelegramStoreProvider,
  WatchlistStoreProvider, UserStoreProvider, RegistryStoreProvider,
  AuditStoreProvider, BillingStoreProvider, TickerServiceProvider,
  PaperEngineProvider, RiskGuardProvider

`*kc.Manager` satisfies all 11 (transparently via existing accessors).
Consumers can depend on the narrow contract for tests/adapters.

---

## 2. Decomposition candidates surveyed

### Candidate 1: Order use-case fields (Wave D Slice D2-D6 hoist)

**Status**: Already extracted from per-request to startup-once Manager
fields. No further decomp needed; this is the post-Wave-D state.

**Scope**: 13 use-case fields:
- placeOrderUC, modifyOrderUC, cancelOrderUC (Slice D2)
- placeGTTUC, modifyGTTUC, deleteGTTUC (Slice D3)
- closePositionUC, closeAllPositionsUC (Slice D4)
- getOrderMarginsUC, getBasketMarginsUC, getOrderChargesUC (Slice D5)
- getPortfolioForWidgetUC, getAlertsForWidgetUC (Slice D6)

**Verdict**: **No further decomp needed**. Wave D Phase 1 is closed
per existing narration. These fields are stable and well-documented.

### Candidate 2: Clock / Timer wiring (now resolvable via clockport extension)

**Empirical**: Manager has no direct clock dependency in its struct.
`kc/fill_watcher.go` already migrated from testutil → clockport in
Path A.27 (commit `68bda0a`). Manager itself uses `time.Now()` directly.

**Could-extend**: If Manager wants a single time source for all init
helpers (e.g., session expiry, token rotation timestamps, audit
timestamps), the kc.Manager could gain a `Clock clockport.Clock` field
defaulting to `clockport.RealClock{}`.

**Verdict**: **Defer**. Not blocking. Would be a small architectural
upgrade (~1d work) but no current pain. Mention as future enhancement.

### Candidate 3: OAuth manager wiring (the 311-LOC manager_commands_oauth.go)

**Empirical**: kc/manager_commands_oauth.go registers OAuth-flow
commands on the CommandBus. The corresponding test file
`manager_commands_oauth_adapters_test.go` is 618 LOC — heavy adapter
test surface.

**Reads**: Manager.commandBus, m.SessionSvc, m.tokenStore,
m.credentialStore, m.userStore, m.registryStore, m.familyService

**Could-extract**: A new `OAuthCommandRegistrar` service holding only
the dependencies above + a back-pointer to commandBus. Manager would
just create+initialize it via a new init helper.

**Cost**: ~1d work (move 311 LOC + update test imports)

**Verdict**: **Medium leverage**. The 7 narrow deps suggest a clean
seam. But it doesn't fundamentally reduce Manager's surface — it just
moves 311 LOC from one Manager file to a service file with a Manager
back-pointer (same pattern as scheduling_service.go).

### Candidate 4: Admin command registration (the 533-LOC manager_commands_admin.go)

**Empirical**: Largest single file in kc/manager_*.go set. Registers
admin RBAC tools on CommandBus.

**Reads**: Manager.commandBus, m.AlertSvc, m.SessionSvc, m.userStore,
m.auditStore, m.billingStore, m.invitationStore, m.familyService,
m.riskGuard

**Could-extract**: A new `AdminCommandRegistrar` service holding the
9 narrow deps above + back-pointer to commandBus.

**Cost**: ~1.5d work (move 533 LOC + update test imports +
admin_*_test.go realignment)

**Verdict**: **Highest leverage by LOC**. But same architectural
pattern as Candidate 3 — just moves LOC, doesn't eliminate Manager
back-pointer pattern.

### Candidate 5: Reconstitution (the 215-LOC manager_reconstitution.go)

**Empirical**: Event-sourcing replay logic. Reads m.eventStore,
m.eventDispatcher, m.alertStore, m.SessionSvc, m.userStore.

**Could-extract**: A `ReconstitutionService` service.

**Cost**: ~1d work (move 215 LOC + update test imports)

**Verdict**: **Medium leverage**. Self-contained domain, narrow deps,
clean boundary.

### Candidate 6: Session reconciliation (within session_service.go's 566 LOC)

**Empirical**: kc/session_service.go is the largest already-extracted
service. Standalone (no Manager back-pointer in struct). The
reconciliation logic (token rotation, lifecycle handoffs, expired
session cleanup) is internal to session_service.

**Could-extract**: Split session_service into `SessionLifecycleService`
(already exists at 120 LOC) + `SessionReconciliationService` (new,
~200 LOC) + `SessionRegistryService` (the active-session map, ~150
LOC).

**Cost**: ~2d work (split single file into 3 + retest all
session-flow tests)

**Verdict**: **Medium leverage**. session_service.go is the largest
single-file concern. Split would clarify responsibilities, but the
file is already standalone (no back-pointer) — refactor is internal
splitting, not coupling reduction.

### Candidate 7: Broker dispatch coordinator (the broker_services.go facade)

**Empirical**: kc/broker_services.go is a facade with back-pointer
holding KiteClientFactory + Instruments + Ticker + PaperEngine +
RiskGuard handles.

**Could-extract**: Eliminate the back-pointer by making BrokerServices
a struct that owns the handles directly (Manager passes them in at
construction; BrokerServices doesn't reach back into Manager).

**Cost**: ~0.5d work — small refactor; the handles are already
discrete fields

**Verdict**: **High leverage / low cost**. This is the cleanest seam
for "make a facade independent of Manager" — Phase 1 of the larger
back-pointer-elimination work.

### Candidate 8: Init helper extraction (the 16 init* methods)

**Empirical**: 16 init methods in manager_init.go totaling ~530 LOC.
Each takes Config and mutates Manager fields.

**Could-extract**: Each could move to a corresponding service-of-
init-helpers file (e.g., initAlertSystem → AlertSystemInitializer).

**Cost**: ~3d work (move 16 helpers + maintain phase ordering +
preserve test setup paths in 16 _test.go files)

**Verdict**: **Low leverage**. The init helpers are *already* well-
structured (16 named units, 530 LOC, phase-ordering documented).
Splitting them across files adds friction (have to navigate 16 files
to read constructor) for no architectural gain.

### Candidate 9: 78-file consumer migration to focused interfaces

**Empirical**: 78 production .go files reach `*kc.Manager`. Existing
ISP work in manager_interfaces.go provides 11 focused contracts. But
many call sites still take `*kc.Manager` directly.

**Could-extract**: Migrate consumer signatures from `*kc.Manager` to
specific interface (e.g., a tool that needs only credentials takes
`CredentialStoreProvider` instead of `*kc.Manager`).

**Cost**: ~2-4 weeks (touches 78 files + reverse-dep tests; each
migration is independent, can be batched)

**Verdict**: **Highest architectural leverage**. Eliminates the
god-struct's blast radius progressively. But this is the multi-week
work the user already anticipated; not a single-dispatch decomp.

---

## 3. Priority order for execution dispatches

### Tier 1 (highest leverage / lowest cost)

**Tier-1.1: Broker services back-pointer elimination** (Candidate 7)
- Cost: ~0.5d
- Eliminates one of three remaining facade back-pointers
- Low risk: small file (133 LOC), no consumer changes
- Pattern: Manager passes handles at construction; BrokerServices
  becomes a struct of pointers, not a facade-with-back-pointer
- Sets precedent for Tier-1.2 + Tier-1.3

**Tier-1.2: Eventing service back-pointer elimination** (similar
shape to broker_services)
- Cost: ~0.5d
- Same pattern; eliminates second of three back-pointer facades
- Risk: low

**Tier-1.3: Scheduling service back-pointer elimination** (mutates
m.sessionManager — slightly trickier)
- Cost: ~1d (because of the m.sessionManager mutation; need
  Manager-passes-empty-registry-in pattern)
- Eliminates third remaining back-pointer facade
- Risk: medium (the mutation is load-bearing for Phase order in
  manager_init.go)

After Tier 1: All 5 facades + 8 standalone services = 13 services,
**none with back-pointers**. Manager becomes a pure aggregate of
services. Total cost: ~2d.

### Tier 2 (medium leverage / medium cost)

**Tier-2.1: Reconstitution service extraction** (Candidate 5)
- Cost: ~1d
- Self-contained domain; clean boundary
- Risk: low

**Tier-2.2: OAuth command registrar extraction** (Candidate 3)
- Cost: ~1d
- 311 LOC into a focused service
- Risk: medium (618-LOC test file needs careful migration)

**Tier-2.3: Admin command registrar extraction** (Candidate 4)
- Cost: ~1.5d
- 533 LOC into a focused service (largest single decomp)
- Risk: medium (admin tests have heavy E2E flavor)

After Tier 2: ~1059 LOC moved out of `kc/manager_commands_*.go` into
focused services. Total cost: ~3.5d.

### Tier 3 (highest leverage / highest cost — multi-week)

**Tier-3: 78-file consumer migration to focused interfaces**
(Candidate 9)
- Cost: 2-4 weeks
- Migrates `*kc.Manager` consumers to ISP contracts
- Risk: medium-high (touches every consumer; can be batched in 5-10
  PRs)
- Outcome: god-struct's blast radius shrinks; consumers depend on
  narrow contracts; tests use minimal fakes

### Deferred

- **Candidate 1** (Wave D Slice D2-D6): already done; no work
- **Candidate 2** (Clock/timer): low pain currently; defer unless
  motivated by a concrete use case
- **Candidate 6** (Session reconciliation split): internal split of
  already-standalone service; defer unless session_service.go's 566
  LOC becomes a maintenance pain
- **Candidate 8** (Init helper extraction): no architectural gain;
  do not pursue

---

## 4. Halt-rules / dependency-graph blockers per candidate

| Candidate | Blocker | Mitigation |
|---|---|---|
| 7 (broker svc back-ptr) | None — handles are discrete fields already | Direct extraction |
| 1.2 (eventing back-ptr) | None — similar to broker_services | Direct extraction |
| 1.3 (scheduling back-ptr) | `s.m.sessionManager = sessionManager` mutation in `initialize()` | Pass empty registry from Manager; service populates it; Manager re-reads |
| 5 (reconstitution svc) | None — self-contained domain | Direct extraction |
| 3 (oauth registrar) | 618-LOC test file with adapter wiring | Phased — extract registrar then migrate tests |
| 4 (admin registrar) | 533-LOC + admin_*_test.go E2E coverage | Phased — extract per-command-group then consolidate |
| 9 (consumer migration) | Each file independent; only constraint is keeping kc.Manager satisfying all interfaces during transition | Phased over 5-10 PRs; tests + canary deploy per PR |

---

## 5. Recommended next dispatch

**Tier-1.1: Broker services back-pointer elimination** (~0.5d).

Rationale:
- Smallest decomp candidate (133 LOC affected)
- Lowest risk (no consumer signature changes; all consumers reach
  via m.brokers.X() which preserves transparently)
- Sets precedent for Tier-1.2 + 1.3 (same pattern, predictable cost)
- Empirically validates "facade-without-back-pointer" pattern
  before committing to the larger admin/oauth registrar work in
  Tier 2

After Tier-1 lands cleanly (~2d), reassess. Tier 2 + Tier 3 can
proceed in parallel via separate dispatches; the high-leverage
Tier-3 (consumer migration) can be batched into 5-10 PRs run by
multiple agents over weeks.

---

## 6. What this dispatch did NOT do (per "research-only" rule)

- No source mutations
- No new files in kc/, app/, mcp/, or .research/scripts/
- No git commits to anything except this design doc
- No execution of any of the candidates surveyed
- No empirical validation that any candidate's design will hold
  under WSL2 build (that is the next dispatch's responsibility)

The empirical-gate methodology that has held for 27+ Path A
promotions still applies for any execution dispatch downstream.

## 7. Time accounting

- Phase 2 dispatch start: ~13:00 IST
- Survey + design completion: ~14:30 IST
- Total time used: ~1.5h
- Inside Phase 2 budget (2h target / 3h halt)
- Inside cumulative Phase 1+2 budget (~6h cap; already at ~6h with
  Phase 1 = 2h + Path A.27 = 2.5h + Phase 2 = 1.5h = 6h)

---

## Decision tree for the orchestrator

After reading this design doc:

1. **If user wants minimum-risk continuation**: dispatch Tier-1.1
   (broker services back-pointer elimination) as first execution
   dispatch. ~0.5d work. Sets precedent.

2. **If user wants highest-leverage architectural cleanup**:
   dispatch Tier-3 (78-file consumer migration to ISP interfaces)
   as a multi-week project. Can be split across multiple agents.

3. **If user wants to defer further decomp**: accept current state
   as good-enough. The 27 algo2go modules + 1 orchestrator structure
   is shipped + validated. The ~3.7k-LOC kc/manager_*.go is a
   well-organized 18-file decomposition, not a god-struct anymore.

4. **If user wants more research**: dispatch a deeper survey on a
   specific tier (e.g., "give me the per-PR migration plan for
   Tier-3 consumer migration").

The architecture has matured significantly through PR 6.15 + Wave D
Slice D2-D6 + Path A.1-A.27. Further decomp is incremental
refinement, not blocked-on-fundamentals.
