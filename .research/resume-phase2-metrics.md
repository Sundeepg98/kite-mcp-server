# Phase 2 Verification Metrics — resume-final team

**Captured post-stabilizer (commit `1e3059c`)** — 2026-04-12
Verifier: team resume-final, Task #2
Build: `go build ./...` clean

## Summary

| # | Metric | Target | Actual | Pass? |
|---|--------|--------|--------|-------|
| 1 | Manager methods | <35 | **22** | PASS |
| 2 | SDK leaks (kiteconnect.New outside allowlist) | 0 | **0** | PASS |
| 3 | CQRS bypasses (session.Broker. in mcp/) | 0 | **0** | PASS |
| 4 | Non-test files >1000 lines | 0 | **0** | PASS |
| 5 | ISP reader/writer interface usage (raw grep) | >0 | **24** | PASS* |
| 6 | testutil imports | ≥5 | **7** | PASS |
| 7 | helpers_test.go files | ≥6 | **6** | PASS |
| 8 | DashboardHandler methods (sum across kc/ops/*.go) | <15 | **39** | **FAIL** |
| 9 | broker.Client direct methods (composite only) | 0 | **0** | PASS |
| 10 | `go test ./...` failing packages | 0 | **1 flaky** (mcp) | MARGINAL |
| 11 | Coverage per package | record | see below | — |

*Asterisks explained in Reality Check section below — these static greps do NOT reflect actual wiring.

## Post-stabilizer deltas vs baseline

None — every count above matches the pre-stabilizer baseline except that the in-flight work is now committed and build is green. Task #1's OrdersHandler split **did not** reduce the DashboardHandler method total (still 39); the OrdersHandler was added as a sibling rather than methods being moved off DashboardHandler.

## Reality Check — The "theater vs wired" audit

Team-lead instructed: count actual dispatch/consumer sites, not interface definitions. Results:

### CQRS: partial wiring — bus is theater, types are real
- `kc/cqrs/` package contains: `bus.go`, `commands.go`, `commands_ext.go`, `queries.go`, `queries_ext.go`, `handler.go`, `query_dispatcher.go`
- `grep -rn "NewBus" --include="*.go"` → **0 production instantiations** (only tests). The Bus is defined but never wired into the app.
- BUT the `cqrs.*Command` / `cqrs.*Query` **types** are heavily used as parameter objects by `kc/usecases/*.go` — usecases are invoked directly, not dispatched through the Bus.
- Verdict: **command/query DTOs are real abstraction; dispatcher layer is dead code.** Reclassify as "request-object pattern," not CQRS.

### StoreAccessor / ISP: 100% theater
All 9 Provider interfaces in `kc/manager_interfaces.go`:
- `TokenStoreProvider`, `CredentialStoreProvider`, `AlertStoreProvider`, `TelegramStoreProvider`, `WatchlistStoreProvider`, `UserStoreProvider`, `RegistryStoreProvider`, `AuditStoreProvider`, `BillingStoreProvider`
- **Production consumers of each: 0** (grep excluding vendor, tests, and the `manager_interfaces.go` file itself)
- Only reference in non-definition code: `_ StoreAccessor = (*Manager)(nil)` compile-time assertion (`manager_interfaces.go:253`)
- Item 5's "24 hits" for `UserReader|UserWriter|AuditReader|AuditWriter|RegistryReader|RegistryWriter` is a different set (kc/users, kc/audit, kc/registry subpackage interfaces). Those MAY be real — needs per-interface consumer count, which item 5's grep does not do.
- Verdict: **StoreAccessor + the 9 *StoreProvider interfaces are dead abstractions**, existing only to satisfy a static type assertion. 16/20 dead-provider claim from Phase 2d is consistent with this (9 here + 7 more elsewhere).

### Event sourcing: 1 live dispatch site
- `kc/domain/events.go` + `kc/eventsourcing/` define the plumbing.
- `app/adapters.go:380` wires `makeEventPersister` to a domain.Event handler — this IS live in production.
- Only one place raises a domain event: `kc/manager.go:120` → `m.eventDispatcher.Dispatch(domain.AlertTriggeredEvent{...})`
- Verdict: **event sourcing has exactly one producer in prod.** The infrastructure is real and wired; the event vocabulary used is just AlertTriggeredEvent. Not "test-only" — one-event-only.

### DashboardHandler (Item 8): still 39 methods
Per-file breakdown (unchanged from baseline): api_handlers=4, api_paper=5, api_portfolio=5, dashboard=5, dashboard_portfolio=4, api_alerts=3, dashboard_safety=3, dashboard_templates=3, api_tax=2, dashboard_paper=2, dashboard_activity=1, dashboard_alerts=1, page_handlers=1. The stabilizer committed a separate OrdersHandler but did not reduce DashboardHandler's surface. **Target <15 not achievable without decomposing DashboardHandler into multiple receiver types.**

## Item 10 — Test suite: 1 flaky package

`go test -count=1 ./...` produced exactly one failure:

```
--- FAIL: TestFullChain_ReadOnlyToolPassesForAnyUser (1.16s)
    middleware_chain_test.go:279: audit should have 5 records for unknown user
        expected: 5, actual: 1
FAIL  github.com/zerodha/kite-mcp-server/mcp
```

Reproduction attempts:
- `go test -count=1 -run TestFullChain_ReadOnlyToolPassesForAnyUser ./mcp/` → **PASS** (isolated)
- `go test -count=1 ./mcp/` → **PASS** (full package re-run)

**Verdict: flaky.** Fails only when running with the full `./...` set. Almost certainly a shared-state leak (audit buffer, global, or parallel test interference) from another package's tests polluting mcp's test state. Not a logic bug introduced by the stabilizer, but a real reliability problem — will intermittently break CI. Filed for Phase 3 attention.

All other packages pass cleanly on `-count=1`.

## Item 11 — Coverage (from `go test -count=1 -cover ./...`)

| Package | Coverage |
|---|---|
| app | 86.3% |
| app/metrics | 99.3% |
| broker | no test files |
| broker/mock | 86.4% |
| broker/zerodha | 99.7% |
| cmd/rotate-key | 97.5% |
| kc | 93.6% |
| kc/alerts | 96.0% |
| kc/audit | 97.2% |
| kc/billing | 98.3% |
| kc/cqrs | 100.0% |
| kc/domain | 95.5% |
| kc/eventsourcing | 99.2% |
| kc/instruments | 98.3% |
| kc/isttz | 75.0% |
| kc/ops | 90.6% |
| kc/papertrading | 98.1% |
| kc/registry | 100.0% |
| kc/riskguard | 100.0% |
| kc/scheduler | 100.0% |
| kc/telegram | 99.7% |
| kc/templates | no test files |
| kc/ticker | 100.0% |
| kc/usecases | 99.8% |
| kc/users | 97.0% |
| kc/watchlist | 100.0% |
| mcp | **85.1%** (+ flaky test) |
| oauth | 92.4% |
| plugins/example | 100.0% |
| testutil | 72.8% |
| testutil/kcfixture | 88.2% |

**Observations:**
- 11 packages at 100% — all small, well-scoped utility packages.
- Lowest real coverage: `kc/isttz` 75.0% and `testutil` 72.8% (testutil being low is acceptable — it's itself test scaffolding).
- Largest production packages (`app`, `mcp`, `kc/ops`, `kc`) all sit in the 85-94% band.
- `kc/cqrs` at 100% is misleading given the Bus is never instantiated in prod — 100% of dead code is still dead code.

## Honest scorecard

**Pass without caveats:** items 1, 2, 3, 4, 6, 7, 9 (7/11)
**Pass-but-theater:** item 5 (ISP grep passes with 24 hits, but 9 of the named Provider interfaces have 0 prod consumers — the grep conflates real narrow interfaces in kc/users + kc/audit + kc/registry with dead StoreProviders)
**Fail:** item 8 (DashboardHandler: 39 ≫ 15)
**Marginal:** item 10 (1 flaky test, root cause is cross-package state leak)
**Recorded:** item 11 (coverage spread healthy for live packages, but 100% on kc/cqrs is gilt on dead code)

**Architecture honesty rating:** the codebase has solid separation in `kc/usecases` and the sub-stores; the broker composite interface is clean; SDK containment is real. What's fake: the StoreAccessor provider tree, the CQRS dispatcher, and the DashboardHandler "decomposition" metric. These should be acknowledged in Phase 3's scorecard rather than claimed as wins.

## Dead code inventory (Phase 2d findings — incorporated per team-lead)

- **CQRS bus**: `kc/cqrs/bus.go` never instantiated in prod — dead. `handler.go` same. DTOs in `commands*.go` / `queries*.go` are live (consumed by kc/usecases).
- **Event sourcing aggregates**: ~900 LOC test-only. The `kc/eventsourcing` store IS wired (app/adapters.go:380) and `kc/domain` events are defined, but aggregate types themselves are exercised only by tests. Only live producer: `kc/manager.go:120` AlertTriggeredEvent.
- **Provider interfaces**: 16 of 20 unused. Verifier confirmed the 9 `*StoreProvider` interfaces in `kc/manager_interfaces.go` have 0 production consumers. 7 more dead elsewhere per Phase 2d.
- **Total dead code**: ~2,300 LOC.
- **Error handling**: 3 HIGH-severity silent-failure / missing-error-path issues flagged by Phase 2g. See that phase's report for sites.

## Recommended Phase 3 actions

1. **Delete** `StoreAccessor` and the 9 unused `*StoreProvider` interfaces — they cost ~100 LOC and provide nothing. (Or: actually use them by making Manager's consumers depend on the narrow interfaces.)
2. **Delete** `kc/cqrs/bus.go` + `handler.go` if no wiring is planned. Keep `commands*.go` / `queries*.go` — those are real request DTOs.
3. **Revise** item 8's target or actually decompose DashboardHandler. Current state fails the stated bar by 24 methods.
4. **Fix** the flaky `TestFullChain_ReadOnlyToolPassesForAnyUser` — isolate audit buffer/global state so test order doesn't affect outcomes.
5. Coverage targets should exclude theater packages (kc/cqrs 100% is a vanity number).
