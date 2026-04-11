# Test Coverage Report

Last updated: 2026-04-11

## Summary

| Package | Coverage | Ceiling | Notes |
|---------|----------|---------|-------|
| `broker/mock` | 100.0% | 100% | Pure mock implementation |
| `broker/zerodha` | 100.0% | 100% | HTTP mocked |
| `kc/cqrs` | 100.0% | 100% | Pure domain logic |
| `kc/domain` | 100.0% | 100% | Value objects, no I/O |
| `kc/registry` | 100.0% | 100% | In-memory + SQLite store |
| `kc/scheduler` | 100.0% | 100% | Timer-based scheduler |
| `kc/ticker` | 100.0% | 100% | WebSocket ticker with mocks |
| `plugins/example` | 100.0% | 100% | Reference plugin |
| `kc/riskguard` | 99.7% | ~100% | 1 unreachable default branch |
| `kc/eventsourcing` | 99.2% | ~100% | Event store replay edges |
| `kc/watchlist` | 98.9% | ~99% | |
| `kc/telegram` | 97.8% | ~98% | Telegram bot API callbacks |
| `kc/audit` | 96.4% | ~97% | SQL `rows.Err()` paths unreachable in-memory |
| `kc/alerts` | 95.6% | ~96% | `defaultBrokerProvider` methods (4 funcs, 0%) call real Kite API |
| `kc/instruments` | 95.7% | ~96% | HTTP download paths |
| `kc/billing` | 95.1% | ~96% | Stripe webhook edge cases |
| `kc/users` | 94.6% | ~96% | |
| `kc/papertrading` | 91.7% | ~93% | Background fill monitor timing |
| `kc/ops` | 75.5% | ~80% | HTTP handler rendering with templates |
| `oauth` | 87.6% | ~90% | Browser-based OAuth flows |
| `kc` (root) | 86.6% | ~87% | Kite API calls in `CompleteSession`, `OpenBrowser` |
| `mcp` | 82.3% | ~85% | MCP tool handlers require full broker session |
| `cmd/rotate-key` | 82.3% | ~83% | `main()` is CLI wrapper; `run()` at 96.3% |
| `app` | 78.5% | ~80% | HTTP server lifecycle |
| `kc/isttz` | 75.0% | 75% | Panic guard is unreachable (see below) |

## Modules at 100%

Eight modules have complete coverage with no unreachable code:

- **`broker/mock`** -- Pure mock broker implementation, all methods return test data.
- **`broker/zerodha`** -- Zerodha broker adapter with HTTP test server mocking all Kite API endpoints.
- **`kc/cqrs`** -- Command/query separation types, pure domain logic with no I/O.
- **`kc/domain`** -- Value objects (INR, InstrumentKey, events). No external dependencies.
- **`kc/registry`** -- App registry store (in-memory + SQLite). All branches testable.
- **`kc/scheduler`** -- Cron-like scheduler with timer-based execution. Fully mockable.
- **`kc/ticker`** -- WebSocket ticker service with connection mocking.
- **`plugins/example`** -- Reference MCP plugin implementation.

## Documented Unreachable Lines

### `kc/isttz` -- 75.0% (ceiling: 75%)

**Line 13**: `panic("failed to load Asia/Kolkata timezone: " + err.Error())`

This panic guard fires only when the Go runtime cannot load `time.Location("Asia/Kolkata")`. This is unreachable because:
- Go embeds tzdata since Go 1.15 via `time/tzdata`
- The Docker image includes the Alpine `tzdata` package
- No Go platform ships without timezone data

Subprocess-based testing (`exec.Command` with custom `ZONEINFO`) could theoretically trigger it, but would test Go's timezone loading rather than our code. The 75% coverage accurately reflects the untestable panic line.

### `cmd/rotate-key` -- `main()` at 0%

**Lines 15-29**: The `main()` function is a 14-line CLI wrapper:
```go
func main() {
    flag.Parse()
    if *dbPath == "" || *oldSecret == "" || *newSecret == "" {
        flag.Usage()
        os.Exit(1)
    }
    if err := run(...); err != nil {
        log.Fatal(err)
    }
}
```

All business logic lives in `run()` (96.3%) and `rotateTable()` (90.7%). Testing `main()` requires process-level testing (`exec.Command` + exit code assertions) which adds complexity without validating any logic not already covered by `run()` tests.

### `kc/alerts` -- `defaultBrokerProvider` at 0%

**Lines 33-55**: Four methods (`GetHoldings`, `GetPositions`, `GetUserMargins`, `GetLTP`) on `defaultBrokerProvider` are thin wrappers around the real `kiteconnect.Client`. They exist solely to satisfy the `BrokerDataProvider` interface with the real Kite API. Tests use `mockBrokerProvider` instead.

### `kc/audit` -- SQL error paths (~3.6% uncovered)

**Various `rows.Err()` and `rows.Close()` error returns** across `List`, `ListOrders`, `GetOrderAttribution`, `GetToolCounts`, `GetToolMetrics`, `GetTopErrorUsers`. These defensive checks guard against I/O errors during SQLite row iteration. With in-memory SQLite, `rows.Err()` never returns a non-nil error because there are no I/O failures.

### `cmd/rotate-key` -- `rotateTable` error paths (~9.3% uncovered)

**Lines 119-120** (scan error), **124-125** (rows.Err), **137-138** (encrypt error), **156-157** (update exec error). These guard against database corruption, schema mismatches, and disk I/O failures. With in-memory SQLite and valid AES keys, these paths cannot be triggered.

### `cmd/rotate-key` -- `run()` open DB error (1 line uncovered)

**Line 35-36**: `sql.Open` with the modernc SQLite driver never returns an error (it opens lazily). The error surfaces on first query, which is covered.

## What Would Be Needed for Higher Coverage

### To reach ~95% across all packages

1. **`kc` root (86.6% -> 95%)**: Extract `SessionService.CompleteSession` to use a `KiteSessionGenerator` interface rather than calling `kiteData.Kite.Client.GenerateSession` directly. This would allow injecting a mock that returns a successful session without hitting the real Kite API. Same pattern needed for `OpenBrowser` (inject `BrowserOpener` interface).

2. **`mcp` (82.3% -> 95%)**: MCP tool handlers call `manager.GetOrCreateSession` which needs a live broker. A `ManagerInterface` extraction or test-mode flag that injects mock sessions would unlock tool handler testing.

3. **`oauth` (87.6% -> 95%)**: The Google SSO callback and Kite OAuth token exchange require real HTTP redirects. A `TokenExchanger` interface would allow mocking the OAuth2 token exchange step.

4. **`app` (78.5% -> 95%)**: The HTTP server lifecycle (`ListenAndServe`, graceful shutdown) requires integration-level tests with real TCP listeners.

### To reach true 100%

In addition to the interface extractions above:

5. **SQL `rows.Err()` paths**: Require a custom `database/sql` driver wrapper that injects I/O errors during iteration. Libraries like `go-sqlmock` can do this, but add a dependency and significant test complexity for code that is inherently defensive.

6. **`kc/isttz` panic line**: Require removing `time/tzdata` from the build and setting `ZONEINFO` to a nonexistent path in a subprocess test. Tests the Go runtime, not our code.

7. **`cmd/rotate-key/main()`**: Require `exec.Command`-based process tests that verify exit codes and flag parsing. The 14-line wrapper delegates entirely to `run()`.

8. **`kc/alerts/defaultBrokerProvider`**: Require a live Kite API key and access token, or wrapping the kiteconnect client behind an interface (which would change 23+ tool handlers).

## Test Counts

| Package | Approximate Test Count |
|---------|----------------------|
| `kc/alerts` | 330+ |
| `kc/audit` | 120+ |
| `kc` (root) | 200+ |
| `oauth` | 150+ |
| `mcp` | 100+ |
| `kc/users` | 80+ |
| `kc/riskguard` | 60+ |
| `broker/zerodha` | 50+ |
| `kc/instruments` | 40+ |
| Other packages | 200+ |
| **Total** | **1300+** |
