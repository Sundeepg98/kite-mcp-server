# testutil/ Research — Mock Patterns Analysis

## Existing Mock Patterns in the Codebase

### Pattern 1: broker/mock.Client (in-memory mock broker)
**Location**: `broker/mock/client.go` (non-test, importable)
**What it does**: Full `broker.Client` interface implementation with in-memory state. Set* methods + error injection fields. Thread-safe.
**Used by**: kc/manager DevMode, mcp/ tests, app/ tests via `WithDevMode()`
**Key insight**: This operates at the **broker abstraction layer** (broker.Profile, broker.Holding, etc.), NOT at the HTTP/Kite API layer. When DevMode=true, the Manager uses this instead of kiteconnect.Client.

### Pattern 2: httptest Kite API servers (per-package, varied)
These are ad-hoc httptest servers that mimic the Kite Connect HTTP API (JSON envelope `{"status":"success","data":...}`). Each package has its own:

- **kc/ops/factory_test.go** — `startDashboardMockKite()` + `newDashboardWithMockKite(t, mockURL)`. Uses `testKiteClientFactory` to inject `SetBaseURI`. Handles: /user/profile, /user/margins, /portfolio/holdings, /portfolio/positions, /orders, /trades, /quote, /gtt/triggers.
- **kc/ops/api_handlers_test.go** — `newMockKiteServer()` + `newMockKiteClient(mockURL)`. Separate mock with different response data. Handles: /user/profile, /portfolio/holdings, /portfolio/positions, /orders, /orders/{id}, /quote, /trades, /user/margins.
- **kc/telegram/handler_test.go** — `fakeKiteAPI` struct with configurable `responses` map (path -> data). Most flexible of the three. Used via `h.kiteBaseURI = fakeAPI.server.URL`.
- **app/server_test.go** — `mockKiteAPIServer(t)` — only handles /session/token for GenerateSession.

### Pattern 3: BrokerDataProvider (interface mock)
**Location**: `kc/alerts/briefing.go` defines the interface; tests use a mock struct implementing it.
**What it does**: Abstracts GetHoldings/GetPositions/GetUserMargins/GetLTP at a Go-interface level, no HTTP. Clean DI pattern.
**Used by**: Briefing service tests, P&L snapshot tests.

### Pattern 4: mockKiteManager (for Telegram)
**Location**: `kc/telegram/handler_test.go`
**What it does**: Implements the `KiteManager` interface that the Telegram BotHandler depends on. Provides API keys, access tokens, and validation results.
**Key insight**: This mocks the Manager itself, not the Kite HTTP API.

### Pattern 5: KiteClientFactory injection
**Location**: `kc/kite_client.go` defines the interface; `kc/ops/factory_test.go` uses `testKiteClientFactory`.
**What it does**: Replaces the factory that creates kiteconnect.Client instances, pointing them at a mock URL. The Manager has a `kiteClientFactory` field.
**Key insight**: This is the designed-in test seam for Manager-level tests that need real HTTP round-trips through gokiteconnect.

## Analysis: Is a centralized testutil/ the right approach?

### What testutil/ provides that IS useful
1. **NewTestManager factory** — eliminates 5+ scattered `newTestManager` variants with identical boilerplate (instruments config, logger, cleanup). This is pure DRY value.
2. **DefaultTestData()** — standard instruments data (INFY, RELIANCE, SBIN) reused everywhere.
3. **DiscardLogger()** — trivial but avoids `io.Discard` boilerplate.

### What testutil/ provides that has ISSUES
1. **MockKiteServer** — This duplicates the existing per-package mock HTTP servers, but MISSES a critical detail: the gokiteconnect SDK routes `/quote/ltp` and `/quote/ohlc` calls through `/quote` (see `kc/ops/factory_test.go` lines 106-117). Our MockKiteServer registers `/quote/ltp` and `/quote/ohlc` as separate endpoints, which won't work with the SDK's actual HTTP calls.
2. The per-package mocks differ in response data for good reasons — each tests different scenarios. A centralized "realistic default" response may not match what each package's tests expect.

### Trade-offs

| Centralized testutil/ | Per-package mocks |
|---|---|
| DRY: one NewTestManager factory | Each package duplicates 15-20 lines of setup |
| Single point of maintenance for defaults | Each mock tailored to its package's exact needs |
| Importable across packages | Stays local to its test file |
| **Risk**: SDK routing mismatch (/quote vs /quote/ltp) | Each package owner handles the details |
| **Risk**: changing defaults breaks tests in other packages | Changes are local |

### Verdict

The **NewTestManager factory** is clearly the right call — it eliminates real duplication with no risk. Every test file has the same 15-line boilerplate.

The **MockKiteServer** is useful but needs a fix: the `/quote/ltp` and `/quote/ohlc` routes must also be served under `/quote` (a single handler matching the SDK's actual behavior). The configurable Set* approach is fine since tests override defaults anyway.

However, the per-package mocks (kc/ops, kc/telegram) should NOT be replaced by testutil.MockKiteServer because:
- They test package-specific HTTP handlers (dashboard handlers, telegram commands) that need custom response shapes
- The `fakeKiteAPI` pattern in telegram is more flexible (responses map)
- The `testKiteClientFactory` in ops/ is the designed-in KiteClientFactory seam

**Recommendation**: testutil/ provides NewTestManager + MockKiteServer for NEW tests and for packages that currently have no mock (mcp/, app/). Existing per-package mocks in kc/ops/, kc/telegram/, kc/alerts/ should NOT be migrated — they work and are tailored.

## Can test files import testutil/?

Yes. Go test packages can import any non-test package. `testutil/` files are NOT `_test.go` files, so they're importable by any package's tests. This is the standard Go pattern (see `testing/fstest`, `net/http/httptest`).

## SDK Routing Bug in Current testutil/

**CRITICAL**: The gokiteconnect SDK's `GetLTP()` and `GetOHLC()` methods call the endpoint `/quote` (not `/quote/ltp` or `/quote/ohlc`). They use the `URIGetQuote` constant and pass an `?i=` query parameter. This is documented in the ops test comments.

Current MockKiteServer registers separate `/quote/ltp` and `/quote/ohlc` handlers. These will NEVER be hit by the SDK. The mock must handle `/quote` and return a combined response format.
