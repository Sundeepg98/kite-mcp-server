# Phase 2j: Wire Dead Code as Real Infrastructure

**Task:** Convert "architecture theater" (files that exist but have no production callers) into real, wired infrastructure. Scope was the dead-code audit from Task #6.

**Status:** Beachhead complete. ~250 LOC of true-dead code removed, 3 subsystems wired.

## Summary of Changes

### DELETED (truly orphaned)

| File | Lines | Why dead |
|---|---|---|
| `kc/manager.go` (pnlService field) | 1 | Duplicate of real wiring in `kc/alert_service.go`; never assigned, never read |
| `kc/usecases/admin_usecases.go` | ~140 | `AdminListFamilyUseCase`, `AdminInviteFamilyMemberUseCase`, `AdminRemoveFamilyMemberUseCase` — never consumed by any tool. Real family admin path lives in `mcp/admin_family_tools.go` with a separate `uStore.ListByAdminEmail` + `FamilyInvitation` flow |
| `kc/usecases/usecases_edge_test.go` | ~110 | 12 orphan tests for the three deleted usecases (1 List + 5 Invite + 6 Remove) |

Note: a teammate restored the three matching DTOs in `kc/cqrs/commands.go` / `queries.go` (`AdminInviteFamilyMemberCommand`, `AdminRemoveFamilyMemberCommand`, `AdminListFamilyQuery`) after my delete. I respected that decision — they're now orphan DTOs but may anchor a future rewrite.

### WIRED (dead code → production)

#### 1. `mcp/retry.go` — `RetryBrokerCall` generic helper

Previously: defined, fully tested, zero production callers.
Now: wraps **3 Kite read call sites** (all were raw `GetLTP` previously):

| File | Line | Call site |
|---|---|---|
| `mcp/alert_tools.go` | 176 | Percentage-alert reference-price fetch |
| `mcp/watchlist_tools.go` | 395 | Watchlist enrichment LTP batch |
| `mcp/ext_apps.go` | 572 | Extension apps LTP pagination (broker.Client type, kept its own `broker.LTP` return type) |

Each now retries up to 2 times (400ms total worst-case) on transient errors via `RetryBrokerCall`.

#### 2. `kc/cqrs/bus.go` — `InMemoryBus` + `LoggingMiddleware`

Previously: 114 LOC of bus + middleware + dispatcher, fully unit-tested, zero production wiring.
Now:
- `Manager` struct holds `commandBus *cqrs.InMemoryBus` and `queryBus *cqrs.InMemoryBus` (initialized in `kc.New` with `LoggingMiddleware`).
- Accessors: `Manager.CommandBus()`, `Manager.QueryBus()`.
- `Manager.registerCQRSHandlers()` (called at end of `kc.New`) registers `GetPortfolioQuery` → `GetPortfolioUseCase.Execute`.
- `mcp/get_tools.go` `HoldingsTool.Handler` (the beachhead) now dispatches via `manager.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{...})` instead of constructing the use case inline.

Every `*kc.Manager` produced by `kc.New()` — including test managers — now has a live bus with at least one registered handler.

### Still TODO (deferred — out of beachhead scope)

1. **7 remaining `NewGetPortfolioUseCase` call sites** in `mcp/tax_tools.go`, `mcp/rebalance_tool.go`, `mcp/sector_tool.go`, `mcp/dividend_tool.go`, `mcp/analytics_tools.go` (×3), `mcp/get_tools.go` (`PositionsTool`). Same refactor pattern, mechanical.
2. **Event-sourcing read path** (`kc/eventsourcing/` aggregates). A tool like `get_order_event_history` that replays `OrderAggregate.Apply(events)` would turn the append-only store into a real read model. Didn't attempt — aggregate types are test-only right now and wiring them deserves its own PR.
3. **16 unused `Provider*` interfaces** in `kc/manager_interfaces.go`. ISP says "narrow at the consumer". These need per-consumer narrowing, which is much bigger than bus wiring.
4. **Command side of bus.** Only `QueryBus` has a handler wired; `CommandBus` is empty. `PlaceOrderCommand` → `PlaceOrderUseCase` is the obvious next candidate.

## Verification

```
go vet ./...                # clean
go build ./...              # clean
go test ./kc/cqrs/ ./kc/usecases/ ./mcp/   # PASS (mcp: 6.5s)
```

`kc/` and `app/` test failures on my Windows environment are unrelated:
- `TestNewConfigConstructor/validation`, `TestManager_MoreAccessors`, `TestNew_*` — HTTP 429 from `api.kite.trade/instruments.json` (tests hit live Kite API)
- `app` package — Smart App Control blocked test binary (Windows issue, not code)

## Dead-Code Metrics Delta

| Metric | Before (Task #6 audit) | After | Delta |
|---|---|---|---|
| `mcp/retry.go` callers | 0 | 3 | +3 |
| `cqrs.NewInMemoryBus` callers | 0 | 1 (in `kc.New`) | +1 |
| `cqrs.LoggingMiddleware` callers | 0 | 1 | +1 |
| Dead admin-family usecases | 3 | 0 | -3 |
| Dead manager.pnlService field | 1 | 0 | -1 |
| Tests for deleted usecases | 12 | 0 | -12 |
| CQRS query handlers registered | 0 | 1 | +1 |

`deadcode` tool should now show `cqrs.InMemoryBus.Dispatch`/`DispatchWithResult`/`Register`, `RetryBrokerCall`, `LoggingMiddleware`, and `GetPortfolioUseCase` all as reachable from `main`.

## Files Touched

- `D:\kite-mcp-temp\kc\manager.go` (bus fields, accessors, `registerCQRSHandlers`, removed pnlService field, imports)
- `D:\kite-mcp-temp\kc\usecases\admin_usecases.go` (deleted 3 orphan usecases)
- `D:\kite-mcp-temp\kc\usecases\usecases_edge_test.go` (deleted 12 orphan tests)
- `D:\kite-mcp-temp\mcp\alert_tools.go` (wired `RetryBrokerCall`)
- `D:\kite-mcp-temp\mcp\watchlist_tools.go` (wired `RetryBrokerCall`)
- `D:\kite-mcp-temp\mcp\ext_apps.go` (wired `RetryBrokerCall`)
- `D:\kite-mcp-temp\mcp\get_tools.go` (`HoldingsTool` → QueryBus dispatch)

## Architecture Impact

- **CQRS score:** was ~33% (types existed but no dispatcher wired). Now there's a real bus in `Manager`, and at least one read-side flow (`get_holdings` → `GetPortfolioQuery`) is CQRS-compliant end-to-end. The remaining 7 portfolio callsites are mechanical migrations.
- **Retry policy:** was ad-hoc at three LTP sites (no retries). Now all three go through a single typed helper with exponential backoff and transient-error detection.
- **Dead code reduction:** ~250 LOC removed outright; another ~150 LOC (retry + bus) moved from "tested but unused" to "tested and in the hot path".
