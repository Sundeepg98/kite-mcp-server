# Task #1 — Fix 3 SDK leaks

Owner: hex-fix
Status: completed

## Summary

Removed production code paths that bypassed `KiteClientFactory` and called
`kiteconnect.New()` directly. Production now wires the factory from
`kcManager.KiteClientFactory()` through to briefing, P&L, and telegram
handlers. The only remaining non-test call sites are the canonical factories
themselves (`kc/kite_client.go`, `broker/zerodha/factory.go`) and shared
test infrastructure in `testutil/`.

## Files changed

1. `kc/alerts/briefing.go`
   - Removed SDK fallback in `defaultBrokerProvider.newClient`. It now
     returns `errNoKiteClientFactory` when no factory is wired, instead
     of silently constructing a raw `kiteconnect.Client`.
   - All four `BrokerDataProvider` methods (`GetHoldings`, `GetPositions`,
     `GetUserMargins`, `GetLTP`) now propagate that error.
   - Added `(*BriefingService).SetKiteClientFactory` so bootstrap wiring
     can inject the factory.
   - Updated the `kiteClientFactory` field comment to say it is required,
     not optional.

2. `kc/alerts/pnl.go`
   - Added `kiteClientFactory` field to `PnLSnapshotService`.
   - `broker()` now constructs `&defaultBrokerProvider{factory: s.kiteClientFactory}`
     instead of `&defaultBrokerProvider{}` with nil factory.
   - Added `(*PnLSnapshotService).SetKiteClientFactory` setter.

3. `kc/telegram/bot.go`
   - Removed the `kiteconnect.New(apiKey)` fallback branch in `newKiteClient`.
     When `h.kiteClientFactory` is nil the handler now returns a user-visible
     error message instead of silently constructing a raw client.
   - Updated field and constructor doc comments.

4. `app/wire.go`
   - `briefingSvc.SetKiteClientFactory(kcManager.KiteClientFactory())` after
     construction.
   - `pnlService.SetKiteClientFactory(kcManager.KiteClientFactory())` before
     registering the scheduler task.

5. `kc/telegram/commands_test.go`
   - Added package-local `testKiteClientFactory` (trivial wrapper around
     `kiteconnect.New` / `SetAccessToken`) so tests can exercise the
     `newKiteClient` path without importing the parent `kc` package (which
     would create an import cycle).
   - Updated `newTestBotHandler` to pass `testKiteClientFactory{}` instead
     of `nil`.

## Verification

```
$ grep -rn "kiteconnect\.New(" --include="*.go" | grep -v _test.go | grep -v vendor
broker/zerodha/factory.go:29:     kc := kiteconnect.New(apiKey)
broker/zerodha/factory.go:35:     kc := kiteconnect.New(apiKey)
broker/zerodha/factory.go:50:     kc := kiteconnect.New(apiKey)
broker/zerodha/factory.go:56:     kc := kiteconnect.New(apiKey)
broker/zerodha/factory.go:72:     kc := kiteconnect.New(apiKey)
kc/kite_client.go:19:     return kiteconnect.New(apiKey)
kc/kite_client.go:23:     kc := kiteconnect.New(apiKey)
testutil/kiteserver.go:109:     kc := kiteconnect.New(apiKey)
```

Count: **8 total**
- `broker/zerodha/factory.go` — 5 (canonical broker factory)
- `kc/kite_client.go` — 2 (canonical Manager factory, wired into Manager.kiteClientFactory)
- `testutil/kiteserver.go` — 1 (`MockKiteServer.Client`, shared test infra
  that cannot be a `_test.go` file because multiple packages import it)

Zero leaks in `kc/alerts/`, `kc/telegram/`, or anywhere else in production code.

```
$ go vet ./kc/alerts/... ./kc/telegram/...
(clean, no output)

$ go test ./kc/alerts/ -count=1
ok      github.com/zerodha/kite-mcp-server/kc/alerts    1.262s

$ go test ./kc/telegram/ -count=1
ok      github.com/zerodha/kite-mcp-server/kc/telegram  1.635s
```

The existing `TestDefaultBrokerProvider_*` tests in `briefing_test.go`
still pass: they call `p := &defaultBrokerProvider{}` (nil factory) and
`require.Error(t, err, ...)`. They now hit `errNoKiteClientFactory`
instead of a network failure, which still satisfies the assertion.

Note: `go vet ./...` at the repo root reports duplicate-method errors
in `kc/manager.go` vs `kc/broker_services.go` / `kc/eventing_service.go`.
These are unrelated to Task #1 — they come from Task #7 (Manager
decomposition) which is in-progress on another teammate.
