# Phase 1: Stabilize — Build Fix

## Problem
105 uncommitted files from previous session. `go build ./...` failed with:

```
kc\ops\dashboard.go:76:47: d.activityAPI undefined
kc\ops\dashboard.go:77:54: d.activityStreamSSE undefined
kc\ops\dashboard.go:78:54: d.activityExport undefined
```

Task 23 (DashboardHandler split) had moved activity handlers to a new
`ActivityHandler` struct in `kc/ops/api_activity.go` but left the routing
in `kc/ops/dashboard.go` still calling the old methods on `DashboardHandler`.

## Fix

1. `NewDashboardHandler` now initializes `d.activity = newActivityHandler(d)`
   (the field already existed on the struct, only the wiring was missing).
2. `RegisterRoutes` updated to dispatch via the sub-handler:
   - `d.activityAPI` → `d.activity.activityAPI`
   - `d.activityStreamSSE` → `d.activity.activityStreamSSE`
   - `d.activityExport` → `d.activity.activityExport`

No other stale references found — other `api_*.go` and `dashboard_*.go`
files already use methods still defined on `DashboardHandler` directly.

## Verification
- `go build ./...` clean
- `go vet ./...` clean
- `go test ./kc/ops/` → ok (3.9s)
- `go test ./...` → all packages pass (kc/ needed `GOTMPDIR=D:/kite-mcp-temp/.gotmp`
  to sidestep Smart App Control blocking unsigned test binaries in the default
  temp dir — pre-existing Windows quirk, unrelated to this fix)
