# Dead Code + Unused Interface Audit — Phase 2d

**Date:** 2026-04-12
**Owner:** deadcode (team resume-final)
**Tooling:** `deadcode ./...` (golang.org/x/tools), `staticcheck -checks=U1000`, targeted grep
**Scope:** `D:\kite-mcp-temp` — 371 `.go` files (228 non-test + 143 test)
**Mode:** read-only — report only, no edits

Raw deadcode output saved to `.research/resume-dead-code-raw.txt` (168 unreachable funcs).

---

## 0. Executive summary

| Category | Count | Severity |
|---|---|---|
| Unreachable production funcs (never called from `main`) | 168 | MED-HIGH |
| Staticcheck U1000 (unused after test inclusion) | 24 | LOW |
| Interfaces declared, zero external consumers | ~16 | MED |
| Dead subsystems (entire files orphaned) | 4 | HIGH |
| Commented-out code blocks | 0 | — |
| TODO / FIXME / HACK comments | 0 | — |
| `// Deprecated:` annotations | 1 | LOW |

**Headline finding:** Four entire subsystems compile, are tested, and ship in the binary but have **zero production callers**:

1. `kc/eventsourcing/{alert,order,position}_aggregate.go` — full DDD aggregate pattern with ~26 funcs, never invoked
2. `kc/cqrs/bus.go` + `query_dispatcher.go` — CQRS bus/dispatcher, never instantiated
3. `mcp/registry.go` — plugin registration + lifecycle hooks, never used at runtime
4. `kc/ops/handler_{account,alerts,paper,pnl,safety}.go` — five empty scaffolding stubs (type + ctor, no methods)

Additionally, 3 admin family usecases in `kc/usecases/admin_usecases.go` duplicate `kc/family_service.go` functionality and are never wired into any tool handler.

These represent ~1,500 lines of architectural-ambition code that was never plumbed through. They inflate the line count, mislead architecture reviewers ("look, we have CQRS + ES!"), and continue to incur test maintenance cost.

---

## 1. Dead subsystems (HIGH severity)

### 1.1 Event sourcing aggregates — 100% test-only

**Files:** `kc/eventsourcing/{alert_aggregate,order_aggregate,position_aggregate,aggregate}.go` (~900 LOC)

`EventStore` itself is used (`app/wire.go:145: eventStore := eventsourcing.NewEventStore(alertDB)`) as a passive audit log. But **every aggregate type — AlertAggregate, OrderAggregate, PositionAggregate — is only instantiated from internal `*_test.go` files**. `NewOrderAggregate` is called 20+ times in `kc/eventsourcing/store_test.go` and `aggregate_edge_test.go`; zero calls from `app/`, `mcp/`, `kc/usecases/`, or `kc/manager*`.

Dead funcs (from deadcode):
- `NewAlertAggregate`, `AlertAggregate.{Create,Trigger,Delete,CanTrigger,CanDelete,Apply,AggregateType}`, `LoadAlertFromEvents`, `deserializeAlertEvent`, `ToAlertStoredEvents`
- `NewOrderAggregate`, `OrderAggregate.{Place,Modify,Cancel,Fill,CanModify,CanCancel,CanFill,Apply,AggregateType}`, `LoadOrderFromEvents`, `deserializeOrderEvent`, `ToStoredEvents`
- `NewPositionAggregate`, `PositionAggregate.{Open,Close,CanClose,Apply,AggregateType}`, `LoadPositionFromEvents`, `deserializePositionEvent`, `ToPositionStoredEvents`
- `BaseAggregate.{AggregateID,Version,PendingEvents,ClearPendingEvents,raise,incrementVersion}`
- All 12 `orderPlacedEvent.EventType`, `positionOpenedEvent.OccurredAt`, etc. (event interface impls for dead aggregates)

Plus domain-layer events in `kc/domain/events.go` with the same fate: `OrderFilledEvent`, `PositionOpenedEvent`, `AlertCreatedEvent`, `AlertDeletedEvent`, `SessionCreatedEvent` — all with `EventType()`/`OccurredAt()` methods that nothing calls.

**Impact:** ~26 unreachable funcs. Advertises an event-sourcing architecture that the runtime ignores. The memory entry "architecture fix ES 35%" aligns — this is why ES scores low.

**Recommendation:** Either (a) wire one aggregate end-to-end through an actual command handler (probably OrderAggregate via `place_order.go`), or (b) delete the aggregate files and keep `EventStore` as a simple audit-log sink. Current state is the worst of both worlds.

### 1.2 CQRS bus + query dispatcher — zero instantiations

**Files:** `kc/cqrs/bus.go`, `kc/cqrs/query_dispatcher.go`

The `cqrs` package defines `CommandBus`/`QueryBus` interfaces AND a concrete `InMemoryBus` + `QueryDispatcher`. The interfaces **are** used: 71 files reference `cqrs.*` (command/query DTOs). But the **bus/dispatcher implementation is never constructed**.

Dead funcs:
- `cqrs.NewInMemoryBus`, `InMemoryBus.{Register,Dispatch,DispatchWithResult}`
- `cqrs.LoggingMiddleware`
- `cqrs.NewQueryDispatcher`, `QueryDispatcher.{AddHook,Dispatch}`

Grep confirms: `cqrs.NewInMemoryBus`, `cqrs.LoggingMiddleware`, `cqrs.NewQueryDispatcher` appear in zero non-test files.

**Reality:** the `cqrs` package is used only as a DTO namespace (command/query structs). Usecases in `kc/usecases/` accept these structs directly in `Execute()` methods — no bus involved. This is fine as a pattern, but the bus code is dead weight.

**Recommendation:** Delete `bus.go` + `query_dispatcher.go` + their tests. Keep `cqrs/commands.go` + `cqrs/queries.go` (the DTOs). Consider renaming the package to `commands` or `dto` to reflect what it actually is.

### 1.3 MCP plugin registry — dead at runtime

**File:** `mcp/registry.go`

Defines `RegisterPlugin`/`RegisterPlugins`/`ClearPlugins`/`PluginCount`, tool-execution hook system (`OnBeforeToolExecution`/`OnAfterToolExecution`/`ClearHooks`). Production code never calls any of these. The only non-test caller is the example plugin itself:

```
plugins/example/plugin.go:17: kitemcp.RegisterPlugin(&ServerTimeTool{})
```

But `plugins/example/plugin.go`'s `init#1` is itself marked unreachable — the `plugins/example` package is never imported by `main.go` or `app/`. The registry and the only plugin that would use it are mutually orphaned.

Dead funcs: `RegisterPlugin`, `RegisterPlugins`, `PluginCount`, `ClearPlugins`, `OnBeforeToolExecution`, `OnAfterToolExecution`, `ClearHooks`, `ServerTimeTool.{Tool,Handler}`, `plugins/example.init#1`.

**Recommendation:** Either import `plugins/example` for real and document the plugin extension point, or delete `mcp/registry.go` + `plugins/example/`. Currently it is aspirational infrastructure.

### 1.4 Ops handler scaffolding — empty stubs

**Files:** `kc/ops/handler_{account,alerts,paper,pnl,safety}.go`

Each is identical in shape — about 10 lines containing just a struct and constructor:

```go
type AccountHandler struct { core *DashboardHandler }
func newAccountHandler(core *DashboardHandler) *AccountHandler {
    return &AccountHandler{core: core}
}
```

No methods. staticcheck also flags `core *DashboardHandler` as unused (U1000). The five `new*Handler` funcs are unreachable. This was clearly the start of a DashboardHandler split (Phase 2a "storeaccessor-split") that was abandoned mid-way.

**Recommendation:** Either finish the split (move methods off `DashboardHandler` into each sub-handler) or delete all five files.

---

## 2. Unused interfaces (MED severity)

### 2.1 Manager provider interfaces — 80% decoration

**File:** `kc/manager_interfaces.go` — 20 interfaces

The file defines ~20 interfaces extracted from `*Manager` (apparent ISP-refactor artifact). Compile-time assertions at line 253-256 prove `Manager` satisfies them:

```go
var (
    _ StoreAccessor      = (*Manager)(nil)
    _ AppConfigProvider  = (*Manager)(nil)
    _ MetricsRecorder    = (*Manager)(nil)
    _ ManagerLifecycle   = (*Manager)(nil)
)
```

Grep for external consumers (`kc\.<InterfaceName>` in any other package):

| Interface | External consumers |
|---|---|
| `SessionProvider` | `mcp/common.go:68` |
| `CredentialResolver` | `mcp/common.go:69` |
| `MetricsRecorder` | `mcp/common.go:70` |
| `AppConfigProvider` | `mcp/common.go:71` |
| **All other 16** (StoreAccessor, ManagerLifecycle, MCPServerProvider, AlertDBProvider, RiskGuardProvider, TokenStoreProvider, CredentialStoreProvider, AlertStoreProvider, TelegramStoreProvider, WatchlistStoreProvider, UserStoreProvider, RegistryStoreProvider, AuditStoreProvider, BillingStoreProvider, TickerServiceProvider, PaperEngineProvider, InstrumentsManagerProvider, TelegramNotifierProvider, TrailingStopManagerProvider, PnLServiceProvider) | **zero** |

Only 4 of 20 interfaces have a caller that actually accepts the interface type. The rest are dead abstraction — each adds a compile-time assertion, some doc, and a single pointer-to-method per Manager accessor. They satisfy the letter of ISP ("define the interface on the consumer side") while having no consumer.

**Recommendation:** Delete the 16 unused interfaces. Keep `SessionProvider`, `CredentialResolver`, `MetricsRecorder`, `AppConfigProvider`. The compile-time assertions can go with them. This will remove ~200 LOC and make the manager split visible for what it is.

### 2.2 Other zero-implementation / zero-consumer interfaces

Spot checks via grep on remaining interface names did not find any that are defined but have zero implementations **and** zero consumers. Most large interfaces (`broker.Client`, `UserStoreInterface`, etc.) have both. The only additional suspect is:

- `FreezeQuantityLookup` (`kc/riskguard/guard.go:98`) — consumed by `app/wire.go:97` via `instrumentsFreezeAdapter`, so it is live.

The `kc/interfaces.go` interface zoo (AlertStoreInterface, TelegramStoreInterface, AuditWriter/Reader/Streamer/Store, BillingStoreInterface, UserReader/Writer/AuthChecker/Store, Registry*, CredentialStoreInterface, TokenStoreInterface, WatchlistStoreInterface, TickerServiceInterface, PaperEngineInterface, InstrumentManagerInterface) was not exhaustively verified but sampled ones are all consumed somewhere in `mcp/` or `kc/usecases/`. No red flags from sampling.

---

## 3. Dead exported functions (MED severity)

These are public, reachable from the test binary (so staticcheck is silent), but unreachable from `main`:

### 3.1 Retry + transient detection
- `mcp/retry.go:10: RetryBrokerCall[T]` — generic retry wrapper with 5 test cases
- `mcp/retry.go:29: isTransientError` — companion classifier

Every broker call in `mcp/*_tools.go` now goes through the ToolHandler middleware path; none wrap calls in `RetryBrokerCall`. **The retry strategy was removed but the implementation was not**.

### 3.2 Zerodha factory
- `broker/zerodha/factory.go: NewFactory, Factory.{BrokerName, Create, CreateWithToken}`

`broker.Factory` interface has no live implementer in production. `app/wire.go` constructs Kite clients directly via `kc.KiteClientFactory`. The `zerodha.Factory` exists only to satisfy its own test file (`client_test.go:1741`).

### 3.3 Legacy Manager constructor
- `kc/manager.go:491: NewManager(apiKey, apiSecret, logger)`

Production uses `kc.New(kc.Config{})` (wire.go:28). `NewManager` survives because `kc/manager_test.go` uses it extensively. This is a maintenance tax — the test surface pins an API that ships in the binary but is unreachable.

### 3.4 Session registry / signer test constructors
- `kc/session.go:81: NewSessionRegistryWithDuration`
- `kc/session_signing.go:53: NewSessionSignerWithKey`
- `kc/session_signing.go:177: SessionSigner.getSecretKey`

Same pattern — heavy test coverage (20+ test callers each), zero production callers. Prod uses the default-duration/default-key constructors.

### 3.5 Scheduler helpers
- `kc/scheduler/scheduler.go: SetClock, SetTickInterval, IsTradingDay, TodayIST, NowIST`

`Scheduler.SetClock`/`SetTickInterval` are clock-injection hooks used by tests, unreachable from runtime. `IsTradingDay`, `TodayIST`, `NowIST` are standalone helpers never called.

### 3.6 Alerts + testing helpers
- `kc/alerts/briefing.go:134: BriefingService.SetBrokerProvider` — mock-injection seam, ~10 test callers, zero prod
- `kc/alerts/telegram.go:96: EscapeMarkdown` — no callers anywhere, even in tests
- `kc/alerts/testing_helpers.go: SetNewBotFuncForTest, RestoreNewBotFunc, OverrideNewBotFunc` — `OverrideNewBotFunc` has the only `// Deprecated:` comment in the repo pointing to the other two, which are themselves unreachable. Self-deprecating dead code.

### 3.7 Admin family usecases (duplicated logic)
- `kc/usecases/admin_usecases.go:{162,497,542}: NewAdminListFamilyUseCase, NewAdminInviteFamilyMemberUseCase, NewAdminRemoveFamilyMemberUseCase`

Three full usecase types + Execute methods with ~80 LOC each and comprehensive test coverage (`usecases_edge_test.go` has ~10 tests). **Never wired into any MCP tool or HTTP handler.** The live family logic is in `kc/family_service.go` (also used by `mcp/admin_family_tools.go`). This is a parallel implementation abandoned before cutover.

### 3.8 Misc
- `kc/billing/tiers.go:104: HasExplicitTier`
- `kc/papertrading/monitor.go:34: Monitor.Stop` — monitor can't be stopped at runtime, only tests call it
- `kc/domain/instrument.go:36: ParseInstrumentKey`
- `kc/domain/spec.go: And, Or, Not, AndSpec.{IsSatisfiedBy, Reason}, OrSpec.{IsSatisfiedBy, Reason}, NotSpec.{IsSatisfiedBy, Reason}` — full specification-pattern combinators never used
- `mcp/cache.go:72,79: ToolCache.Size, ToolCache.Clear` — cache lifecycle methods never called (cleanup goroutine handles everything)
- `mcp/common.go:229: ToolHandler.callWithNilKiteGuard`
- `mcp/correlation_middleware.go:16: CorrelationIDFromContext`
- `mcp/elicit.go:28: isConfirmableTool` — the elicit subsystem runs but this helper is orphaned
- `mcp/setup_tools.go:19: isAlphanumeric`
- `mcp/ticker_tools.go:285: resolveTickerMode`
- `oauth/handlers.go:171: Handler.SetHTTPClient` — HTTP client injection seam unused

---

## 4. Staticcheck U1000 (unused identifiers)

After including test files, staticcheck finds 24 unused items. Most are test-helpers whose only caller was deleted:

| File:line | Kind | Notes |
|---|---|---|
| `app/server_test.go:5413` | `func mockKiteAPIServer` | test helper, no callers |
| `app/telegram_test.go:21-31` | `type mockBotAPI` + 2 methods | orphan mock |
| `kc/alerts/helpers_test.go:16` | `func testLogger` | duplicate, unused |
| `kc/helpers_test.go:25` | `func newKiteClientWithMock` | orphan helper |
| `kc/manager.go:466` | `field pnlService` | unused struct field in production type |
| `kc/manager_edge_test.go:2206` | `type failBrokerSessionService` | orphan mock |
| `kc/ops/handler_*.go:5` ×5 | `field core` | all five empty ops-handler stubs |
| `kc/ops/helpers_test.go:23` | `func testLogger` | duplicate |
| `kc/ops/ops_admin_test.go:63` | `func adminCtx` | test helper, unused |
| `kc/watchlist/db_test.go:391` | `field loadOK` | test struct field |
| `mcp/context_tool.go:94` | `type apiResult` | defined but unused |
| `mcp/option_tools.go:130` | `type optInst` | defined but unused |
| `oauth/google_sso_test.go:805` | `field adminEmails` | test struct field |

**Highest priority:** `kc/manager.go:466 field pnlService is unused` — a production struct field tagged unused. Worth investigating whether this is a legit gap (PnL service should be wired) or safely removable.

---

## 5. Commented-out code blocks

`^\s*/\*` yielded **zero** matches across the .go tree. There are no block-commented-out code regions. Single-line comments with "remove", "delete", "deprecated" all refer to normal CRUD operations in docstrings, not dead code.

**Only hit:** `kc/alerts/testing_helpers.go:15: // Deprecated: Use OverrideNewBotFunc instead.` — the deprecated and its replacement are **both** unreachable (see §3.6).

---

## 6. TODO / FIXME / HACK

**Zero real instances.** Grep for `TODO|FIXME|HACK|XXX|DEPRECATED` returns only test strings (`"XXXX"` as tamper-payload in session signing tests). This is genuinely clean — the earlier security-audit + quality-audit passes cleared these.

---

## 7. Recommended cleanup order

| # | Action | LOC | Risk | Effort |
|---|---|---|---|---|
| 1 | Delete 5 empty `kc/ops/handler_*.go` stubs | ~50 | none | trivial |
| 2 | Delete `mcp/registry.go` + `plugins/example/` | ~150 | low (check for runtime plugin loading) | trivial |
| 3 | Delete 16 unused provider interfaces in `kc/manager_interfaces.go` | ~200 | none (compile-time only) | trivial |
| 4 | Delete `kc/cqrs/bus.go` + `query_dispatcher.go` + their tests | ~300 | low | 30m |
| 5 | Delete `kc/domain/spec.go` combinators (And/Or/Not) | ~100 | none | trivial |
| 6 | Delete `broker/zerodha/factory.go` + test | ~80 | low | trivial |
| 7 | Delete `mcp/retry.go` + `tools_pure_test.go` retry cases | ~60 | MED — re-evaluate whether retries should be re-added at the middleware layer first | 30m |
| 8 | Delete 3 admin family usecases + tests OR wire them in | ~400 | MED — duplication with family_service.go | 1h |
| 9 | Delete ES aggregates (alert/order/position) OR wire OrderAggregate through place_order | ~900 | HIGH — architectural decision | 1-4h |
| 10 | Investigate `kc/manager.go:466 pnlService` unused field — bug or legacy? | — | ? | 15m |
| 11 | Delete scheduler orphans (`IsTradingDay`, `TodayIST`, `NowIST`) | ~20 | none | trivial |
| 12 | Delete `EscapeMarkdown`, `ParseInstrumentKey`, `HasExplicitTier`, orphan test helpers | ~80 | none | trivial |

**Total cleanup potential:** ~2,300 LOC removed, one architectural decision forced (ES aggregates), one latent bug possibly uncovered (pnlService field).

## 8. Notes for Phase 3 scorecard

- **DDD score** should not be inflated by aggregate file count — the aggregates are test-only decoration. Score should count only `family_service.go` + domain VOs that are actually referenced.
- **CQRS score** is DTO-only, not bus-dispatched. That is fine architecturally (usecases call each other directly), but the `cqrs` package name misleads. Either rename or acknowledge "CQRS = command/query DTOs, no bus" in the scorecard.
- **ES score** is `EventStore` audit log, **not** event-sourced aggregates. Current 35% memory score looks right.
- **ISP score** is misleading upward — 20 interfaces in `manager_interfaces.go` is ISP-by-file-count but only 4/20 have consumers.
- **Code hygiene** is excellent — zero TODO/FIXME, zero commented-out blocks, a single `// Deprecated:` annotation. The dead code here is all "structural ambition" dead, not "forgot to clean up after fix" dead.
