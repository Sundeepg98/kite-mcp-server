# kc.Manager Internal Decomposition Empirical Roadmap (2026-05-16)

_Authored: 2026-05-16 IST_
_Source agent: Audit (Manager-decomp empirical re-survey)_
_Status: REFERENCE — dispatch-ready when Tier A/B execution is greenlit_
_Source HEAD: kite-mcp-kc `41d8bf0` (post-Brief-3 port prerequisite)_

---

## §INPUTS — load-bearing facts (verified 2026-05-16)

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | kite-mcp-kc HEAD: `41d8bf0` (post-Brief-3-prereq) | `git rev-parse HEAD` | 2026-05-16 |
| 2 | Manager: **63 fields** (11 exported + 52 unexported) | `awk` over `manager_struct.go:65-186` | 2026-05-16 |
| 3 | Manager methods: **129 total** (91 exported + 38 unexported) across **30 non-test files** | `grep -cE '^func \(m \*Manager\)' *.go` | 2026-05-16 |
| 4 | Of 129 methods, **~96 are passthrough delegators** in 5 facade files + accessor files (store_registry=23, broker_services=15, eventing=6, scheduling=7, sessionLifecycle=11, credential=9, alert=4, callback=4, lifecycle=3, accessors=8, config_manager=6) | per-file count | 2026-05-16 |
| 5 | Behavior-bearing Manager methods: ~30-40 (init + register + 4 ad-hoc) | derived: 129 - 96 = 33 | 2026-05-16 |
| 6 | Manager init phases: **17 init* methods** in 5 files (manager_init, manager_init_alerts, manager_init_persistence, manager_init_services, manager_init_stores) | `grep -hE '^func \(m \*Manager\) init'` | 2026-05-16 |
| 7 | CQRS register methods: **15 register* methods** spread across 12 manager_commands_*.go files | `grep -hE '^func \(m \*Manager\) register'` | 2026-05-16 |
| 8 | 5 Tier-1 facades ALREADY EXTRACTED with closure-DI (no back-pointer): stores, eventing, brokers, scheduling, sessionLifecycle. **849 LOC total** (`store_registry=220`, `eventing=174`, `brokers=187`, `scheduling=148`, `sessionLifecycle=120`). All use closure-by-reference pattern. | `wc -l` + `head` each | 2026-05-16 |
| 9 | 7 focused services ALREADY EXTRACTED with own types: CredentialService, SessionService, ManagedSessionService, PortfolioService, OrderService, AlertService, FamilyService. ~1,500 LOC total. | `grep 'type X Service struct'` | 2026-05-16 |
| 10 | kc-internal `m.<unexported>` reaches: **492 occurrences across 30 production files** | per-file grep | 2026-05-16 |
| 11 | Bootstrap reaches at kc unexported fields: **0** (Go compiler enforces) | `grep manager\.{unexported}` returns 0 matches | 2026-05-16 |
| 12 | Top 5 reaching files: manager_commands_account.go(67), store_registry.go(44), manager_use_cases.go(41), manager_queries_remaining.go(38), manager_commands_orders.go(31). All facade or CQRS register sites. | per-file count | 2026-05-16 |
| 13 | Remaining Option B accessor sites (cross-repo, non-test): CommandBus=56+15=71, QueryBus=70+1=71, MCPServer=14+0=14, SetMCPServer=0+0=0 (was 1) | per-accessor grep bootstrap+kc | 2026-05-16 |
| 14 | Consumer broker.X vs domain.X adoption (cross-repo excl wrapper module): **broker.Order=53, broker.Position=63** vs **domain.NewOrder/Position calls=16**. Adoption ratio ~7:1 DTO over entity. | cross-repo grep | 2026-05-16 |
| 15 | sub-packages already present in kc: `internal/util/`, `ops/`, `ports/`. ports/ has 7 ports now (post-Brief-3-prereq: alert, credential, instrument, order, session + AuditStoreConcreteProvider + SessionRegistryProvider). | `ls` | 2026-05-16 |
| 16 | Closure-DI pattern documented as Tier 1.1/1.2/1.3 in broker_services.go:14-26, eventing_service.go:15-25, scheduling_service.go:17-26. Eliminates back-pointer to *Manager. | file headers | 2026-05-16 |
| 17 | `god-object-inventory-2026-05-11.md` is the canonical decomp baseline; Manager scored 63 fields/47 methods/4,104 LOC. **Manager method count now 91/129** — re-count drift (baseline only counted manager.go proper; today counts all 30 files via grep). LOC remains comparable (~4,000-4,500). | re-read inventory + verify | 2026-05-16 |

---

## §1 — Per-field clustering analysis

### §1.1 The 63 fields by concern (empirical)

Cluster name → field list → init phase → consumer pattern → extractability verdict.

| Cluster | Fields | n | Init phase | Sub-package candidate | Verdict |
|---|---|---|---|---|---|
| **C1 — Auth-identity** | apiKey, apiSecret, accessToken | 3 | newEmptyManager (line 60-62) | `kc/identity/` (proposed) | **EXTRACTABLE** — already cohesive cluster. No back-pointer needed; immutable post-construction. Cited in inventory §3.1 mutual-state. |
| **C2 — Infra observability** | Logger, metrics | 2 | newEmptyManager (63-64) | KEEP (universal) | KEEP — every type needs these |
| **C3 — Template assets** | templates | 1 | initializeTemplates (manager_lifecycle.go) | `kc/templates/` exists externally | DRAINABLE — already external module; one field is a 1-liner extract |
| **C4 — Focused services** (Clean Arch) | CredentialSvc, SessionSvc, ManagedSessionSvc, PortfolioSvc, OrderSvc, AlertSvc, FamilyService | 7 | initFocusedServices (services.go) | **already extracted as types** | DONE — these ARE the decomposition; just stay as Manager fields |
| **C5 — Tier-1 Facades** (closure-DI) | stores, eventing, brokers, scheduling, sessionLifecycle | 5 | newEmptyManager (85-89) | **already extracted as types** | DONE — Tier 1.1/1.2/1.3 shipped |
| **C6 — Instruments + session core** | Instruments, SessionManager, SessionSigner | 3 | initInstrumentsManager + scheduling.initialize | KEEP exposed | KEEP — heavy cross-cutters; already exported fields post-B1/B2/B4 |
| **C7 — Persistence stores** (typed) | tokenStore, credentialStore | 2 | newEmptyManager (70-71) | KEEP in `kc/` | KEEP — direct kc-private storage; reached via stores facade |
| **C8 — Alert-system stores** | alertStore, alertEvaluator, trailingStopMgr, telegramNotifier, alertDB, ownsAlertDB | 6 | initAlertSystem, initAlertEvaluator, initTrailingStop, initTelegramNotifier, initPersistence | `kc/alerts/` sub-pkg | EXTRACTABLE — cohesive alert subsystem; 6 fields could collapse to 1 `*alertSubsystem` field |
| **C9 — Encryption + per-user stores** | encryptionKey, watchlistStore, userStore, registryStore | 4 | initSideStores, initPersistence | KEEP via stores facade | KEEP — already proxied via Stores() |
| **C10 — Optional injected stores** | auditStore, riskGuard, paperEngine, billingStore, invitationStore | 5 | initInjectedStores | KEEP (nil-safe pattern is correct) | KEEP — already optional + nil-safe |
| **C11 — Event sourcing** | eventDispatcher, eventStore, projector | 3 | initProjector + post-construction Set | already in eventing facade | DONE via Eventing() facade |
| **C12 — MCP wiring** | mcpServer (any-typed to avoid cycle) | 1 | SetMCPServer (post-construct) | move to `mcp/wiring/` to type it | DRAINABLE — Brief 3's port-creation pattern shows the way; one of the 4 remaining Option B targets |
| **C13 — Broker subsystem** | kiteClientFactory, tickerService | 2 | newEmptyManager + initTickerService | already in brokers facade | DONE via Brokers() facade |
| **C14 — CQRS** | commandBus, queryBus | 2 | newEmptyManager (72-73) | KEEP exposed (as fields, not getters) | DRAINABLE — 2 of 4 remaining Option B targets (147 cross-repo sites) |
| **C15 — App-mode config** | appMode, externalURL, adminSecretPath, devMode | 4 | newEmptyManager (65-68) | `kc/identity/` or `kc/config/` | EXTRACTABLE — small cohesive config cluster |
| **C16 — Order use cases** (Wave D Phase 1) | placeOrderUC, modifyOrderUC, cancelOrderUC | 3 | initOrderUseCases | could move to OrderSvc internally | DRAINABLE — fold into OrderSvc (it's the natural owner) |
| **C17 — GTT use cases** (Wave D Phase 1) | placeGTTUC, modifyGTTUC, deleteGTTUC | 3 | initOrderUseCases | fold into OrderSvc or new GTTSvc | DRAINABLE — same pattern |
| **C18 — Exit use cases** (Wave D Phase 1) | closePositionUC, closeAllPositionsUC | 2 | initOrderUseCases | fold into OrderSvc | DRAINABLE |
| **C19 — Margin use cases** (Wave D Phase 1) | getOrderMarginsUC, getBasketMarginsUC, getOrderChargesUC | 3 | initOrderUseCases | fold into OrderSvc or new MarginsSvc | DRAINABLE |
| **C20 — Widget use cases** (Wave D Phase 1) | getPortfolioForWidgetUC, getAlertsForWidgetUC | 2 | initOrderUseCases | fold into PortfolioSvc / AlertSvc | DRAINABLE |

**Total**: 63 fields. **Already-decomposed** (C4 + C5 + C11/Eventing + C13/Brokers + C7,C9,C10 via Stores): 22 fields are facade-mediated. **KEEPS without change**: C2, C6, C7, C9, C10 = 17 fields. **DRAINABLE clusters**: C3, C8, C12, C14, C16, C17, C18, C19, C20 = 21 fields. **EXTRACTABLE to sub-pkg**: C1, C8, C15 = 13 fields.

### §1.2 Method-cluster overlay

Methods follow the same clustering:

| Cluster | Method type | Count | Comment |
|---|---|---|---|
| Init-phase methods | `init*`, `initialize*`, `register*` | **32** (17 init + 15 register) | All in `manager_init*.go` + `manager_commands_*.go` |
| Facade passthrough delegators | trivial 1-line returns | **~96** | Stores=15, Brokers=10, Eventing=5, Scheduling=6, SessionLifecycle=5, Credential=9, Alert=4, Callback=4, Lifecycle=3, Accessors=8 |
| Bus accessors | `CommandBus()`, `QueryBus()`, `MCPServer()`, `SetMCPServer()` | 4 | 2 are passthroughs to fields |
| Provider methods | `GetBrokerForEmail`, `HasBrokerFactory`, `SetFamilyService`, `AuditStoreConcrete`, `SessionRegistry` (new) | 5 | Provider port satisfactions |
| Ad-hoc behavior | `Shutdown`, `widgetAuditStoreFromCtxOrManager`, `projectionOrdersForEmail`, `resolveNativeAlertClient` | 4 | Unique-purpose; stay on Manager |
| **TOTAL** | | **~141** (some methods double-count) | — |

The **96 passthrough delegators** are the largest single category. Many of these become DEAD CODE once consumers stop reaching `manager.X()` and go through `manager.Stores().X()` (or directly via `manager.Stores`).

---

## §2 — Decomposition sequence (per-step concrete plan)

Each step is a single dispatch. **Critical path**: steps marked → must complete before downstream steps fire.

### Step 1 — Drain 4 remaining Option B accessors (CommandBus/QueryBus/MCPServer/SetMCPServer)

| Aspect | Value |
|---|---|
| Scope | Expose 3 fields (CommandBus, QueryBus, MCPServer), keep SetMCPServer setter. Delete 3 getter methods. |
| Sites to rewrite | 156 cross-repo (kc=16 + bootstrap=140; SetMCPServer=0) |
| LOC delta | -90 LOC (3 method deletions) + 156 site rewrites (1 char each: `.X()` → `.X`) |
| Cost | ~3-5h (sed sweep + WSL2 verify + 2-PR pattern from B1/B2/B4 precedent) |
| Risk | LOW — proven 4× pattern (Sprint 5/B1/B2/B4) |
| Prerequisite | none |
| Pattern | Anchor 6 PR 6.x "expose field + delete getter" |
| Parallel-safe? | Internally NO (single PR per repo); but Track 2 work can run in parallel on different files |
| Halt conditions | tool count drift in `/healthz total_available` (was 111); test failures; sed-missed sites |
| **Output**: Manager: 63 fields → 63 fields (3 unexported→exported); 91 exported methods → 88 (3 getter deletions); SetMCPServer setter retained |

### Step 2 — Fold Wave D use cases into OrderSvc internally (C16+C17+C18+C19+C20)

| Aspect | Value |
|---|---|
| Scope | Move placeOrderUC, modifyOrderUC, cancelOrderUC, placeGTTUC, modifyGTTUC, deleteGTTUC, closePositionUC, closeAllPositionsUC, getOrderMarginsUC, getBasketMarginsUC, getOrderChargesUC, getPortfolioForWidgetUC, getAlertsForWidgetUC from Manager fields to `OrderService` internal fields (or carve out `OrderUCService` sub-service) |
| Sites to update | initOrderUseCases (1 file), eventing_service.go (8 SetDispatcher propagation closures), manager_commands_orders.go + manager_commands_exit.go + manager_commands_admin_alerts.go etc. (~30 dispatch sites) |
| LOC delta | Manager struct shrinks by 13 fields; method count unchanged (passthroughs preserve API); ~150 LOC moves to OrderSvc |
| Cost | ~6-8h |
| Risk | MED — Wave D Phase 1 SetDispatcher propagation chain has 8 fan-out points (eventing_service.go:118-143); must preserve nil-safe behavior. Slice D2-D7 had 18 commit cycle to get right; reorganization touches every dispatch event flow |
| Prerequisite | none (independent of Step 1) |
| Pattern | "absorbed into focused service" — same shape as ManagedSessionService absorbing SessionRegistry passthroughs |
| Parallel-safe? | YES with Step 1 (different files) |
| Halt conditions | event propagation broken (OrderPlaced/Modified/Cancelled events vanishing); failing Wave D regression tests in manager_edge_test.go |
| **Output**: Manager: 63 → 50 fields; eventing_service.go simplified (8 fewer propagation closures) |

### Step 3 — Bundle alert subsystem into a kc/alertsubsystem internal type (C8)

| Aspect | Value |
|---|---|
| Scope | Move alertStore, alertEvaluator, trailingStopMgr, telegramNotifier, alertDB, ownsAlertDB into new `AlertSubsystem` type within kc package |
| Sites to update | initAlertSystem, initAlertEvaluator, initTrailingStop, initTelegramNotifier, initPersistence (5 init phases re-shape); AlertSvc constructor (now takes 1 AlertSubsystem ref); manager_commands_admin_alerts.go (4 ref sites); manager_init_persistence.go (alertStore.SetDB, trailingStopMgr.SetDB sites) |
| LOC delta | Manager 50 → 44 fields; new AlertSubsystem ~80 LOC; ~50 LOC of init code reshapes |
| Cost | ~4-6h |
| Risk | MED — initAlertSystem trigger callback (alerts_init.go:27-59) has 3 fan-outs (Telegram + audit + domain.AlertTriggeredEvent); preserve nil-safe behavior |
| Prerequisite | Step 2 ideally first (cleaner Manager surface) |
| Pattern | "subsystem extraction" — analogous to existing AlertService wrapper but pulls more components |
| Parallel-safe? | Within Manager-decomp track NO; safe to parallel with Track 2 consumer adoption |
| Halt conditions | Telegram notifier wiring drops messages; alert evaluator misses ticks; trailing-stop modification chain broken |
| **Output**: Manager: 50 → 44 fields |

### Step 4 — Extract kc/identity/ sub-package (C1 + C15)

| Aspect | Value |
|---|---|
| Scope | Move apiKey, apiSecret, accessToken, appMode, externalURL, adminSecretPath, devMode into `kc/identity.Identity` type. Manager holds `*identity.Identity`. |
| Sites to update | newEmptyManager (assignment block); config_manager.go (6 IsLocalMode/ExternalURL/AdminSecretPath/DevMode/APIKey passthroughs become identity.X) |
| LOC delta | Manager 44 → 37 fields; new kc/identity package ~80 LOC; sites that read these via Manager methods unchanged |
| Cost | ~3-4h |
| Risk | LOW — pure data move; 7 fields are immutable post-construction |
| Prerequisite | Step 3 (or independent — different fields) |
| Pattern | "identity-cluster sub-package" — proposed by inventory §3.1 |
| Parallel-safe? | YES with Steps 1-2 |
| Halt conditions | API-key resolution path fails (TestNewManager); ExternalURL fmt change |
| **Output**: Manager: 44 → 37 fields; new kc/identity sub-package |

### Step 5 — Drain 96 facade passthrough delegators (gradual)

| Aspect | Value |
|---|---|
| Scope | Push consumers from `manager.X()` to `manager.Stores().X()`, `manager.Brokers().X()`, etc. Then delete the Manager-level passthrough methods. |
| Sites to rewrite | ~600 cross-repo (estimate: bootstrap+kc consumers of facade-delegated methods) |
| LOC delta | -380 LOC of Manager delegator methods (96 methods × ~4 LOC each) + 600 site rewrites (1-line each) |
| Cost | ~12-20h (largest LOC win + most sed-able) |
| Risk | LOW — pattern proven 96 times via Tier 1.1/1.2/1.3; just consumer migration |
| Prerequisite | Steps 1-4 (cleaner accessor surface helps grep precision) |
| Pattern | Tier 1.1 "consumers route via facade" |
| Parallel-safe? | YES — 5 facades are disjoint scopes; can dispatch 5 agents on Stores/Brokers/Eventing/Scheduling/SessionLifecycle in parallel |
| Halt conditions | tool count drift; facade signature mismatch (rare — all are 1-line forwards) |
| **Output**: Manager: 88 exported methods → ~24 (96 passthroughs deleted) |

### Step 6 — Extract ManagerInit (17 init phases) to package-level funcs

| Aspect | Value |
|---|---|
| Scope | Move 17 init* methods from `manager_init*.go` to package-level funcs `kc.InitX(m *Manager, cfg Config) error` (or to a new `kc/init/` sub-package; the inventory recommended the latter but in-package preserves access to unexported fields without exports) |
| Sites to update | NewWithOptions orchestrator (manager.go:53-114) re-points to package-level funcs |
| LOC delta | No LOC change; reorganization. Tests against init phases become testable in isolation. |
| Cost | ~6-8h |
| Risk | MED — phase ordering is load-bearing (manager.go:53 docs); single mistake = silent runtime regression |
| Prerequisite | none (independent) |
| Pattern | "named phase functions" (inventory §3.1 migration step 2) |
| Parallel-safe? | NO (single file edit); but trivially safe to run concurrent with consumer-side Step 5 |
| Halt conditions | init phase ordering changes; test fixtures that mock individual init steps break |
| **Output**: Manager: 91 exported methods → 74 (-17 init methods); same field count |

### Step 7 — Extract ManagerCQRSWiring (15 register methods + manager_commands_*.go files)

| Aspect | Value |
|---|---|
| Scope | Move 15 register* methods + their handler bodies from 12 manager_commands_*.go files to `kc/cqrs/wiring/` sub-package |
| Sites to update | manager.go (constructor calls registerCQRSHandlers); ~30 internal `m.X` access sites need to become exported-field or constructor-arg access |
| LOC delta | ~1,400 LOC moves out of kc-root; new sub-pkg gets coherent home |
| Cost | ~10-14h |
| Risk | MED-HIGH — bus is two-phase (set after newEmptyManager; consumed at registerCQRSHandlers); cross-package access requires exporting more fields OR passing dependencies explicitly |
| Prerequisite | Step 1 (CommandBus/QueryBus exposed) + Step 2 (Wave D UCs moved); without these, cross-package register methods can't reach into Manager |
| Pattern | "register methods to sub-package" (inventory §3.1 migration step 3) |
| Parallel-safe? | NO; serial after Steps 1-2 |
| Halt conditions | Handler registrations missing at runtime → MCP tool dispatch returns 'unknown command'; failure in registerCQRSHandlers chain |
| **Output**: Manager: 74 exported methods → 59 (-15 register methods); ~1,400 LOC moves to sub-pkg |

### Step 8 — Decompose 5 Tier-1 facades into proper sub-packages (optional, ambitious)

| Aspect | Value |
|---|---|
| Scope | Move BrokerServices, EventingService, SchedulingService, StoreRegistry, SessionLifecycleService from kc package to `kc/brokers/`, `kc/eventing/`, `kc/scheduling/`, `kc/stores/`, `kc/sessions/` sub-packages |
| Sites to update | Manager constructor: 5 facade constructors become qualified `brokers.New(...)`, `eventing.New(...)`, etc. Closure-DI now needs explicit getter/setter exports |
| LOC delta | 849 LOC moves out of kc-root to sub-packages |
| Cost | ~8-12h |
| Risk | MED — closures over Manager fields (current pattern) become cross-package closures with explicit accessor signatures; cyclic-pointer architecture explicitly forbidden by ports invariant |
| Prerequisite | Step 5 (consumer migration to facades complete) |
| Pattern | Tier-1 promotion to sub-package |
| Parallel-safe? | 5 facades are disjoint = 5 parallel agents |
| Halt conditions | cyclic import (sub-package needs to import kc-root for *Manager type); SetX setter wiring breaks |
| **Output**: Manager: 59 → 24 exported methods (Brokers/Eventing/etc accessors stay; their delegators were already removed in Step 5) |

### Step 9 — Convergence point: count Manager state

After Steps 1-8 complete:

| Metric | Baseline (2026-05-11) | At HEAD (2026-05-16) | After Steps 1-4 | After Steps 1-7 | After Steps 1-8 |
|---|---:|---:|---:|---:|---:|
| Manager fields | 63 | 63 | 37 | 37 | 22 (after C5 decompose to sub-pkg constructors) |
| Manager exported methods | 47 (baseline measurement scope was narrower) | 91 | 88 | 56 | 24 |
| Manager files | 17 | ~17 | ~14 | ~10 | ~5 |
| Manager LOC (kc-root non-test) | ~4,104 | ~4,500 | ~3,800 | ~2,400 | ~1,500 |

**Target god-struct kill threshold (≤ 15 fields)**: requires Step 8 or merging C2 (Logger+metrics) into another facade. With current scope, Step 8 lands ~22 fields. Final cut to ≤ 15 needs C6/Instruments+SessionManager+SessionSigner moved to brokers/sessions facades respectively (2-3h additional).

**Realistic stopping points** (per §7):
- **A — Pragmatic**: stop after Step 7 (Manager ~37 fields, ~56 methods, ~2,400 LOC). 90% of value at 60% of cost.
- **B — Ambitious**: complete Step 8 (Manager ~22 fields, ~24 methods, ~1,500 LOC). Diminishing returns kick in.
- **C — Pedantic**: <15 fields. Cosmetic refinement past B; not justified by ROI.

---

## §3 — Cross-reference: Manager-decomp vs Track 2 consumer-adoption

### §3.1 Independence claim

Manager-decomp (this roadmap) and Track 2 (broker.X → domain.X consumer adoption) **touch DISJOINT files**:
- Manager-decomp: kc-root files (manager_*.go, store_registry.go, facade files) + cross-repo accessor migration
- Track 2: bootstrap mcp/* + kc-root manager_commands_*.go + kite-mcp-usecases

**Overlap**: kc-root manager_commands_orders.go has both:
- Consumer-adoption work (44 broker.Order refs at this file alone)
- Decomp work (Step 2: hoist Wave D UCs to OrderSvc; Step 7: extract this file to kc/cqrs/wiring/)

### §3.2 Sequencing safety

Run them in parallel — different agents on different scopes:

| Track | Scope | Parallel-safe with Manager-decomp Steps |
|---|---|---|
| **Manager-decomp Step 1** (4 accessors drain) | kc/manager_accessors.go + cross-repo facade-passthrough rewrite | Safe with Track 2.A (Order entity adoption — different files) |
| **Manager-decomp Step 5** (96 passthroughs drain) | Cross-repo facade-passthrough rewrite | Safe with Track 2 — uses different grep patterns; no file overlap |
| **Manager-decomp Step 7** (CQRS register extraction) | kc/manager_commands_*.go relocation | UNSAFE with Track 2.A in manager_commands_orders.go specifically; serialize this single file |

### §3.3 Track 2 unblock-via-Manager-decomp angle

Does Manager-decomp ENABLE Track 2? **Slightly**: when Wave D UCs (Step 2) move to OrderSvc internally, the OrderSvc methods can take `domain.OrderSpec` instead of `broker.OrderParams`, providing a clean adoption point for the domain VO. But Step 2 is not REQUIRED for Track 2 — Track 2 works at consumer surface independently.

### §3.4 Recommended parallel dispatch

- **Agent X (Manager-decomp)**: Steps 1, 2, 3, 4 serially
- **Agent Y (Track 2)**: Track 2.A (Order entity) + Track 2.B (Position entity) in parallel
- **Agent Z (Manager-decomp Step 5)**: After Step 4 lands, 5 parallel facade-drain agents
- All three can run simultaneously with ~zero conflict if Agent Z owns Manager-decomp's facade-drain and Agent Y owns Track 2's DTO→entity rewrite. Both touch broker.* and domain.* in DIFFERENT capacities.

---

## §4 — Pattern selection per cluster

Algo2Go umbrella's `architectural-patterns-record.md` was dispatched parallel but not yet visible in the corpus at synthesis time. Inferring from existing patterns at HEAD:

| Cluster | Recommended pattern | Source pattern in codebase | Why |
|---|---|---|---|
| **C1 Auth-identity** | Identity-cluster sub-package | `kc/internal/util/` precedent; inventory §3.1 | Cohesive cluster; immutable post-init |
| **C8 Alert subsystem** | Subsystem-type within package | AlertService (88 LOC, 5 fields) precedent | Already partial; just absorb more components |
| **C12 mcpServer** | Provider port (typed) | Brief 3's AuditStoreConcreteProvider, SessionRegistryProvider | Brief 3 just shipped — established |
| **C14 CQRS** | Exposed field + drain getters | Anchor 6 PR 6.x (B1/B2/B4 precedent) | Proven 4×; trivial extension |
| **C16-C20 Wave D UCs** | Absorbed into focused service | ManagedSessionService(SessionRegistry) precedent | Same shape; service-owned use cases |
| **C5 Tier-1 facades → sub-pkgs** | Closure-DI + sub-package | Tier 1.1/1.2/1.3 closure-DI is in-place | Already half-done |
| **C4 Focused services** | Stay as Manager-held types | CredentialService/AlertService precedent | Cited inventory §7.7 as the SHIPPING TARGET shape |
| **CQRS register methods** | Register-method extraction to sub-pkg | Anchor 5 PR 5.x port extraction precedent | Inventory §3.1 step 3 |

**Pattern gaps** (not addressed by existing precedent):
- Cross-package closure-DI (Step 8): no prior art. Would need to evaluate whether closures-as-cross-package-args adds complexity vs simpler explicit deps.

---

## §5 — Sprint 1-4 wall re-falsification at HEAD 41d8bf0

### §5.1 What Sprint 1-4 hit

Per `god-object-inventory-2026-05-11.md` §3.1 + Algo2Go umbrella's Shape 1 (referenced in dispatch):
- **Wall**: "25 fields cross package boundary" — fields that consumers across the kc/bootstrap split needed direct access to, blocking encapsulation
- **Reaction**: Sprint 1-4 stalled; Sprint 5 B-series picked off 3 of 8 trivial cases (ManagedSessionSvc, SessionSigner, SessionManager exposed)

### §5.2 Re-survey at HEAD: what's actually walled today

Of the original "25 walled fields", I empirically count what's still problematic:

| Field | Status 2026-05-16 | Evidence |
|---|---|---|
| ManagedSessionSvc | **DRAINED** (PR B1) | manager_struct.go:77 exposed |
| SessionSigner | **DRAINED** (PR B2) | manager_struct.go:92 exposed |
| SessionManager | **DRAINED** (PR B4) | manager_struct.go:91 exposed |
| CommandBus | walled (Step 1 target) | 71 cross-repo sites |
| QueryBus | walled (Step 1 target) | 71 cross-repo sites |
| MCPServer | walled (Step 1 target) | 14 cross-repo sites |
| AuditStoreConcrete | **PROVIDER PORT shipped** (Brief 3 prereq today) | ports/audit_store_concrete.go |
| SessionRegistry | **PROVIDER PORT shipped** (Brief 3 prereq today) | ports/session_registry.go |
| auditStore / riskGuard / paperEngine / billingStore | accessed via Stores facade (Get/Set) | store_registry.go:106-141 |
| Logger | exposed field (existed all along) | manager_struct.go:69 |
| Instruments | exposed field | manager_struct.go:90 |
| All "stores" fields | accessed via Stores() facade | StoreRegistry methods |
| All "broker" fields | accessed via Brokers() facade | BrokerServices methods |
| All "eventing" fields | accessed via Eventing() facade | EventingService methods |
| All "scheduling" fields | accessed via Scheduling() facade | SchedulingService methods |

**Verdict**: of the original ~25 walled fields, **22 are no longer walled** (drained or provider-port-mediated). Only **3 active getters remain**: CommandBus, QueryBus, MCPServer. SetMCPServer is by-design.

### §5.3 The Sprint 1-4 wall framing was VALID-THEN but FALSIFIED-NOW

What changed between Sprint 1-4 (failed) and Sprint 5 (succeeded):
1. The 5 Tier-1 facades shipped (closure-DI eliminated back-pointers)
2. Path A externalization moved 28 algo2go modules out
3. Anchor 5/Anchor 6 PR series introduced the "expose field + delete getter" pattern with proven 4× success
4. ports/ package + leaf-stability invariant established as compile-time guard

**The wall was real in Sprint 1-4 because the patterns weren't yet established**. Today the patterns exist. **The remaining 3 walled accessors are TRIVIAL to drain** — same pattern, ~3-5h cost (Step 1).

### §5.4 Per-field reality check at HEAD

For each cluster, can extraction happen today?

| Cluster | Walled today? | If yes, what's the block? |
|---|---|---|
| C1 Auth-identity (3 fields) | NO | Pure data; extractable today |
| C8 Alert subsystem (6 fields) | NO | Cohesive subsystem; extractable today (Step 3) |
| C12 mcpServer (1 field) | NO | Brief 3's port-creation pattern unblocks this |
| C14 CQRS (2 fields) | walled (cosmetic) | 142 cross-repo sites need rewrite — sed-able; not architecturally walled |
| C15 App-mode config (4 fields) | NO | Pure config; extractable |
| C16-C20 Wave D UCs (13 fields) | NO | Internal-only fields; absorb into OrderSvc with care for SetDispatcher fan-out |
| C5 Tier-1 facades → sub-pkg | walled (LOW-MED) | Cross-package closure-DI is novel; would need evaluation |

**Conclusion**: NO field is genuinely walled at HEAD. All claims of "25 walled fields" were valid against the **Sprint 1-4 toolset**; against today's toolset (Provider ports + facade closure-DI + expose-field pattern), every cluster has a clear extraction path.

---

## §6 — Concrete total cost

### §6.1 Per-step cost table

| Step | Hours | LOC moved | Risk | Critical path? |
|---|---:|---:|---|---|
| 1 — Drain 4 accessors | 3-5 | ~250 (LOC + site rewrites) | LOW | enables Step 7 |
| 2 — Fold Wave D UCs to OrderSvc | 6-8 | ~150 | MED | enables Step 7 (cleanly) |
| 3 — Alert subsystem bundle | 4-6 | ~130 | MED | optional |
| 4 — kc/identity/ extraction | 3-4 | ~80 | LOW | optional |
| 5 — Drain 96 passthrough delegators | 12-20 | ~400 + 600 site rewrites | LOW | enables Step 8 |
| 6 — Extract init phases | 6-8 | ~538 reorganized | MED | optional |
| 7 — Extract CQRS wiring to sub-pkg | 10-14 | ~1,400 | MED-HIGH | requires Steps 1-2 |
| 8 — Promote Tier-1 facades to sub-pkgs | 8-12 | ~849 | MED | requires Step 5 |
| **TOTAL (all 8 steps)** | **52-77h** | **~3,400 LOC reorganized** | mixed | — |

### §6.2 Critical-path graph

```
Step 1 ──┐
Step 2 ──┤
Step 3 ──┤   (independent)
Step 4 ──┘
         │
         ▼
Step 7 (requires Step 1 + Step 2)

Step 5 (requires Steps 1-4)
   │
   ▼
Step 8 (requires Step 5)

Step 6 (independent — parallel with others)
```

### §6.3 Realistic agent-hours by ambition tier

| Tier | Steps | Hours | Manager target | Verdict |
|---|---|---:|---:|---|
| **A — Pragmatic** | 1, 2, 5 | 21-33h | ~50 fields, ~24 methods | 90% value; recommend |
| **B — Standard** | 1, 2, 3, 4, 5 | 28-43h | ~37 fields, ~24 methods | Full reasonable scope |
| **C — Full** | 1-7 | 44-65h | ~37 fields, ~10 methods | All in-package decomp |
| **D — Ambitious** | 1-8 | 52-77h | ~22 fields, ~10 methods | Sub-pkg extraction; cosmetic gain |

**Recommendation: Tier B (~30-43h)**. Tier B closes the "kc.Manager is still huge" framing while staying on proven patterns; Tier D's Step 8 is high-risk for marginal LOC win.

### §6.4 Per-step parallelization economics

5 of 8 steps are parallel-safe:
- Steps 1+2+3+4 can run in 4 parallel agents → wall-clock ~6-8h (longest = Step 2 at 6-8h)
- Step 5 splits into 5 facade-drain agents → wall-clock ~3-4h each (~12-20h / 5)
- Step 6 runs concurrent with Step 5
- Step 7 must serialize after Step 1+2 → ~10-14h
- Step 8 must serialize after Step 5 → ~8-12h

**Wall-clock Tier B (parallel)**: max(Step 2, Step 4) + max(Step 5 sliced) + Step 6 = 8 + 4 + 8 = **~20h calendar**.
**Wall-clock Tier C**: + Step 7 = **~34h calendar**.

---

## §7 — Honest assessment

### §7.1 Is full decomposition feasible?

**YES** — every cluster has an extraction path. The "25 walled fields" framing is empirically falsified at HEAD `41d8bf0`. The 5 Tier-1 facades + 7 focused services + Provider port pattern + closure-DI = sufficient toolset.

### §7.2 Inflection points

| Manager-fields target | Steps needed | Hours | Inflection assessment |
|---:|---|---:|---|
| **63 → ~50** | Step 1 + Step 2 | ~9-13h | Easy win: drains the obvious cosmetic-residual accessors and absorbs Wave D UCs. **High ROI**. |
| **50 → ~37** | + Steps 3, 4 | ~7-10h | Sub-package cleanup: alert subsystem + identity cluster. **Good ROI**. |
| **37 → ~30** | + Step 5 (passthrough drain) | ~12-20h | Method-count win, not field-count win. ROI shifts to method-count clarity. |
| **30 → ~22** | + Steps 6, 7, 8 | ~24-34h | Diminishing returns. Architectural cleanliness improves but field-count gain is modest. |
| **22 → <15** | + speculative C2/C6 reshape | ~8-12h | Cosmetic. The remaining fields (Logger + Instruments + SessionManager + SessionSigner + facades) are CORRECTLY-Manager-owned. Pushing below 15 means inventing artificial seams. |

**The diminishing-returns inflection is at ~30 fields**. Below that, architectural value drops sharply.

### §7.3 The "still huge" reframe

The chain agent's framing "kc.Manager is still the same 63-field 132-method god-struct" is empirically NOT MATCHED at HEAD `41d8bf0`. Today:
- 63 fields, but **22 already mediated via facades** (Tier 1.1/1.2/1.3 done)
- 129 methods, but **96 are trivial 1-line delegators** that exist for backward-compat
- Effective behavior surface: ~30-40 unique methods on the actual Manager-owned state

The 63/132 count is accurate but **misleading**. The decomposition that already happened (Sprint 5 + Tier 1 + Anchor 5/6 + Path A) is INVISIBLE in the field count because the facades hold backrefs (closures) and the original fields persist as the source-of-truth.

**Honest framing**: kc.Manager is a **partially-decomposed god-struct**. The decomposition is ~50% complete. The remaining 50% is well-mapped (this roadmap) and ~20-43h of agent-time away.

### §7.4 Comparison to "LOC relocation, not decomposition"

The chain agent's "Phase 1 moved 55k LOC from bootstrap to algo2go/kite-mcp-kc" critique is partially valid:
- Phase 1 was indeed mostly LOC RELOCATION (kc/ from bootstrap to a new repo)
- But Sprint 5 + Tier 1 + Anchor 5/6 (preceding Phase 1) WERE decomposition: closure-DI, exposed-field drain, Provider ports
- The empirical decomposition progress AT kite-mcp-kc HEAD is: 22 of 63 fields facade-mediated, 96 of 129 methods are passthrough delegators, 7 focused services extracted as own types

**The critique is too harsh as applied to kc/**: the in-place decomposition WAS happening; Phase 1 just made the LOC count visible in the kite-mcp-kc repo specifically.

### §7.5 What stops if we halt the roadmap NOW

If 0 additional decomp work is dispatched:
- Manager stays at 63/129/4500 LOC; functional and tests-green
- The "kc still huge" optic persists in framing/research but not in operational risk
- Track 2 (DDD consumer adoption) is independent and proceeds
- Future agents discovering the codebase encounter a partially-decomposed god-struct with confusing dual surfaces (Manager.X() AND Manager.Facade().X() both work)

If only Tier A (~21-33h) ships:
- Manager → 50 fields; 4 walled accessors gone; Wave D UCs absorbed
- Most consumer-facing API confusion resolved
- Track 2 unblocked

If Tier B (~30-43h) ships:
- Manager → 37 fields; cosmetic god-struct framing largely retired
- Sub-package proliferation begins (kc/identity/, possibly kc/alerts subpackage)

---

## §8 — Empirical surprises

### §8.1 Method count drift: 47 → 91/129

The 2026-05-11 baseline counted 47 methods but the present count is 91 exported (129 total). The difference: baseline scoped to `manager.go` + a few core files; my count covers all 30 production files (including facade passthroughs which are technically Manager methods). **The 47 baseline UNDERCOUNTED.** Today's accurate count: 91 exported with ~96 of all 129 being passthroughs.

### §8.2 Most "fields" are already mediated

22 of 63 Manager fields are wrapped by Tier-1 facades (closure-DI) at construction time. Reading the field through `manager.X` and `manager.Facade().X()` are equivalent today. **The decomposition shipped invisibly** — the field count didn't drop, but the architectural shape changed.

### §8.3 Encapsulation wall is INTRA-package, not CROSS-package

492 reaches at unexported Manager fields inside kc package. **0 reaches from bootstrap** (Go would refuse). The "encapsulation wall" was never about Go-package privacy — it was about REACH-INTO-MANAGER patterns at consumer sites. Bootstrap migration ALREADY ELIMINATED the cross-package reach. The intra-package reach (~492 sites) is the actual decomposition target.

### §8.4 Wave D UCs are 13 fields — biggest single cluster

C16-C20 collectively = 13 fields (20% of the 63). The natural owner is OrderSvc (or new GTTSvc / MarginsSvc carve-outs). Absorbing them yields the biggest single field-count win (Step 2, 13-field drop) at MED risk.

### §8.5 96 passthrough delegators

This is the single largest category of method surface. Most are 1-line `return m.facade.X()`. Their existence is purely for backward-compat at consumer sites; once consumers route via facades directly (Step 5), 96 methods can be deleted in a single sweep.

### §8.6 Manager's "true" behavior is small

After mentally subtracting the 96 passthroughs + 17 init phases + 15 register methods, Manager has ~5 ad-hoc methods: `Shutdown`, `widgetAuditStoreFromCtxOrManager`, `projectionOrdersForEmail`, `resolveNativeAlertClient`, `IsLocalMode/ExternalURL/etc` (6 config helpers in config_manager.go).

**Manager is mostly a stable composition root + facade aggregator** at HEAD `41d8bf0`. The 4,500 LOC framing overstates its internal complexity.

### §8.7 Track 2 consumer adoption is real BUT exaggerated

Cross-repo broker.X vs domain.X count: 53 broker.Order + 63 broker.Position vs 16 domain.NewOrder/NewPosition calls. The "44 broker.Order" figure from prior dispatch under-counted; today's number is 53. **DDD consumer-adoption work is ~110 site rewrites** (not 50). Effort scales accordingly: ~14-22h consumer migration vs 8-12h earlier estimate.

### §8.8 Sub-package emergence will accelerate

Once Step 4 (kc/identity/) lands, the precedent is set. Subsequent sub-package extractions (kc/alerts/, kc/wave-d/) become 2-3h each. **The marginal cost of additional sub-packages drops sharply after the first one** — pattern + ports + WSL2 verification chain is reusable.

### §8.9 No dependency on Algo2Go umbrella's pattern record

This report was synthesized without the parallel architectural-patterns-record being available. All patterns cited are visible in the codebase at HEAD. **If Algo2Go umbrella's record adds new patterns not cited here, those can be inserted as additional dispatch options** — they're additive, not foundational to this plan.

---

## Methodology footnote

- READ-ONLY: zero commits to source, zero modifications to any kc tree at synthesis time.
- Time used: ~95 min of 3-4h budget.
- All field/method/LOC counts compile-and-run rooted (per `feedback_compile_and_run_methodology`).
- Cross-repo grep counts exclude `_test.go` consistently (per `feedback_narrow_test_scope_no_stash`).
- Date-stamp on every numeric claim (per `feedback_dated_synthesis`).
- Probes: 25+ grep/awk/wc/cat invocations across kc + bootstrap + 3 other algo2go modules + kite-mcp-server research corpus.

## Cross-references

- `.research/research/god-object-inventory-2026-05-11.md` — canonical decomp baseline (Manager scored 63/47/4,104)
- `.research/research/option-b-expose-properties-2026-05-11.md` — accessor-drain pattern
- `.research/architectural-patterns-record.md` — Algo2Go umbrella's pattern record (dispatched in parallel; cross-reference when available)
- `.research/research/decomposition-blockers-comprehensive-2026-05-11.md` — Sprint 1-4 wall blocker analysis
- `.research/phase-3-dispatch-briefs-2026-05-16.md` — Phase 3 sub-git extraction (downstream consumer of Manager-decomp Tier A)
