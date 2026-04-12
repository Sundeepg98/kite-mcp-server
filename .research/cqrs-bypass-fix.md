# Task #5 — Fix 4 CQRS bypasses in mcp/

Owner: hex-fix
Status: completed

## Summary

Replaced all four direct `session.Broker.XXX()` method calls in mcp/
non-test code with the existing CQRS use cases (`GetProfileUseCase`,
`GetOrderHistoryUseCase`, `GetLTPUseCase`) backed by the standard
`sessionBrokerResolver` adapter. No new use cases were introduced —
every replacement uses machinery that already existed.

## Files changed

1. `mcp/common.go`
   - `WithTokenRefresh` middleware: replaced `session.Broker.GetProfile()`
     with `usecases.NewGetProfileUseCase(&sessionBrokerResolver{...})
     .Execute(ctx, cqrs.GetProfileQuery{Email: email})`.
   - Added imports: `kc/cqrs`, `kc/usecases`.

2. `mcp/post_tools.go`
   - `PlaceOrderTool` post-execution fill check: replaced
     `session.Broker.GetOrderHistory(orderID)` with
     `usecases.NewGetOrderHistoryUseCase(...).Execute(ctx, ...)`.
   - Uses the existing `sessionBrokerResolver` pattern that's already
     used throughout this file.

3. `mcp/trailing_tools.go`
   - `SetTrailingStopTool` `current_stop` fallback: replaced
     `session.Broker.GetOrderHistory(orderID)` with
     `GetOrderHistoryUseCase`.
   - `SetTrailingStopTool` `reference_price` fallback: replaced
     `session.Broker.GetLTP(instrumentID)` with `GetLTPUseCase`.
   - Added imports: `kc/cqrs`, `kc/usecases`.

All three files were run through `gofmt -w` to match house style.

## Verification

```
$ grep -rn "session\.Broker\." mcp/ --include="*.go" | grep -v _test.go
mcp/native_alert_tools.go:187:     nac, ok := session.Broker.(broker.NativeAlertCapable)
mcp/native_alert_tools.go:233:     nac, ok := session.Broker.(broker.NativeAlertCapable)
mcp/native_alert_tools.go:403:     nac, ok := session.Broker.(broker.NativeAlertCapable)
mcp/native_alert_tools.go:464:     nac, ok := session.Broker.(broker.NativeAlertCapable)
mcp/native_alert_tools.go:518:     nac, ok := session.Broker.(broker.NativeAlertCapable)
```

**Count of direct-method calls on `session.Broker`: 0** (target was `<=1`).

The 5 remaining hits in `native_alert_tools.go` are NOT method calls —
they are Go type-assertions of the form `session.Broker.(broker.NativeAlertCapable)`
that probe the concrete broker for an optional capability interface. They
don't bypass CQRS; they check whether the broker implements a specific
feature before delegating to capability-specific code. Task spec counted
direct method calls (e.g., `session.Broker.GetProfile()`), not interface
casts, so these are out of scope.

```
$ grep -rn "manager\.Store" mcp/ --include="*.go" | grep -v _test.go
(zero matches)
```

**Count of direct `manager.Store` access: 0.**

## Build / vet status

`gofmt -e` parses all three files cleanly (no syntax errors).

`go build ./mcp/` at the time of this writing fails with duplicate-symbol
errors in `kc/alerts/db_commands.go`, `db_queries.go`, and `db_migrations.go`
— these are left over from Task #11's in-progress work on another teammate
and are unrelated to Task #5. All of my changes are in `mcp/*.go` files;
none touch `kc/alerts`. Once Task #11 finishes consolidating the db split,
`go vet ./mcp/...` can be re-run to confirm.

## Mapping to task spec

| # | Location | Before | After |
|---|---|---|---|
| 1 | `mcp/common.go:147` | `session.Broker.GetProfile()` | `usecases.GetProfileUseCase` |
| 2 | `mcp/post_tools.go:193` | `session.Broker.GetOrderHistory(orderID)` | `usecases.GetOrderHistoryUseCase` |
| 3 | `mcp/trailing_tools.go:117` | `session.Broker.GetOrderHistory(orderID)` | `usecases.GetOrderHistoryUseCase` |
| 4 | `mcp/trailing_tools.go:131` | `session.Broker.GetLTP(instrumentID)` | `usecases.GetLTPUseCase` |
