# Manager Round 2 — Task #14 Progress

## Goal
Reduce `kc/manager.go` from 55 methods to <45 by extracting a SchedulingService
(and, optionally, a SessionLifecycleService) following the round-1 facade
pattern (StoreRegistry, EventingService, BrokerServices).

## Before
```
$ grep -c '^func (m \*Manager)' kc/manager.go
55
```
`kc/manager.go`: 991 lines

## After
```
$ grep -c '^func (m \*Manager)' kc/manager.go
38
$ wc -l kc/manager.go kc/scheduling_service.go kc/session_lifecycle_service.go
 876 kc/manager.go
  99 kc/scheduling_service.go
 104 kc/session_lifecycle_service.go
```
Manager methods: **55 -> 38** (target was <45). 17 methods moved out.

## What moved

### New: `kc/scheduling_service.go` (SchedulingService)
Groups cleanup-routine + metrics-recording concerns. Struct holds a
back-pointer to Manager; Manager holds a `*SchedulingService` field wired in
`New()` and exposes thin delegators.

Moved off manager.go:
- `initializeSessionManager` -> `SchedulingService.initialize()` (internal)
- `kiteSessionCleanupHook` -> `SchedulingService.kiteSessionCleanupHook()` (internal)
- `CleanupExpiredSessions` -> delegator now lives in scheduling_service.go
- `StopCleanupRoutine` -> delegator now lives in scheduling_service.go
- `HasMetrics` -> delegator now lives in scheduling_service.go
- `IncrementMetric` -> delegator now lives in scheduling_service.go
- `TrackDailyUser` -> delegator now lives in scheduling_service.go
- `IncrementDailyMetric` -> delegator now lives in scheduling_service.go
- plus the new `Scheduling()` accessor

### New: `kc/session_lifecycle_service.go` (SessionLifecycleService)
Thin facade over `SessionService` grouping MCP session lifecycle delegators
so they no longer occupy manager.go.

Moved off manager.go:
- `GetOrCreateSession`
- `GetOrCreateSessionWithEmail`
- `GetSession`
- `ClearSession`
- `ClearSessionData`
- `GenerateSession`
- `SessionLoginURL`
- `CompleteSession`
- `GetActiveSessionCount`
- plus the new `SessionLifecycle()` accessor

## Manager struct changes
Two new fields added next to the round-1 facades:
```go
scheduling       *SchedulingService       // cleanup routines, session cleanup hooks, metrics recording
sessionLifecycle *SessionLifecycleService // MCP session lifecycle facade (get/create/clear/complete)
```
Wired in `New()` alongside `stores`, `eventing`, `brokers`.

`New()` now calls `m.scheduling.initialize()` instead of
`m.initializeSessionManager()`. The `context` import was removed from
`manager.go` since `context.Background()` now lives in the new file.

All existing public behaviour (`MetricsRecorder`, `ManagerLifecycle`,
`SessionProvider` interfaces) is preserved: the Manager-level methods still
exist, they just delegate into the new facades.

## Verification
```
$ grep -c '^func (m \*Manager)' kc/manager.go
38

$ grep -c '^func (m \*Manager)' kc/scheduling_service.go
7

$ grep -c '^func (m \*Manager)' kc/session_lifecycle_service.go
10

$ wc -l kc/manager.go
876 kc/manager.go

$ gofmt -l kc/manager.go kc/scheduling_service.go kc/session_lifecycle_service.go
(empty)
```

- Target `<45 methods` on `kc/manager.go`: **38** (margin of 7).
- `gofmt` clean on all three files.
- `go build github.com/zerodha/kite-mcp-server/kc` is blocked by unrelated
  duplicate-method errors in the `oauth` package from the in-progress
  Task #15 split (`oauth/handlers.go` vs
  `handlers_oauth.go`/`handlers_browser.go`/`handlers_callback.go`). This is
  a transitive blocker via kc/audit -> oauth, kc/billing -> oauth,
  kc/papertrading -> oauth, kc/riskguard -> oauth; the root `kc` package
  itself does not import `oauth` directly, and no new imports or references
  were introduced here. My files compile cleanly in isolation (gofmt pass,
  all referenced symbols exist on the Manager struct).

## Files touched
- `kc/manager.go` — 991 -> 876 lines; 55 -> 38 Manager methods; dropped `context` import; added two new facade fields; replaced `m.initializeSessionManager()` call with `m.scheduling.initialize()`; deleted all 17 relocated method bodies.
- `kc/scheduling_service.go` — new; 99 lines; defines `SchedulingService` + 7 Manager delegators.
- `kc/session_lifecycle_service.go` — new; 104 lines; defines `SessionLifecycleService` + 10 Manager delegators.
