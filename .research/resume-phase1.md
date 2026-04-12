# Phase 1 Stabilize — Progress

## Status: DONE

## Root cause
Mid-refactor of `DashboardHandler` decomposition (extract `OrdersHandler`)
was interrupted. `OrdersHandler` struct + all six orders methods already
existed on the new type, but `dashboard.go` and four test files still
called them through the old `*DashboardHandler` receiver.

## Changes (kc/ops/)
- `dashboard.go`
  - Added `orders *OrdersHandler` field on `DashboardHandler`
  - Initialized in `NewDashboardHandler`: `d.orders = newOrdersHandler(d)`
  - Routed three endpoints through `d.orders.`:
    - `/dashboard/orders` -> `d.orders.serveOrdersPageSSR`
    - `/dashboard/api/orders` -> `d.orders.ordersAPI`
    - `/dashboard/api/order-attribution` -> `d.orders.orderAttributionAPI`
- Test call-site fix-ups (moved receiver `d.X` -> `d.orders.X`):
  - `api_handlers_test.go` — 4x enrichOrdersWithKite, 1x buildOrderEntries, 1x buildOrderSummary
  - `dashboard_data_test.go` — 2x buildOrderEntries, 2x buildOrderSummary
  - `handler_edge_test.go` — 1x buildOrderEntries, 2x buildOrderSummary

## Verification
- `go vet ./...` — clean
- `go build ./...` — clean
- `go test ./...` — all packages pass EXCEPT `app` (Smart App Control blocks
  `app.test.exe` from running; environmental Windows issue, not a code bug —
  see CLAUDE.md memory re: SAC unsigned-binary policy)
- `go test ./kc/ops/...` — ok 6.3s (the package we touched)

## Other handler_*.go files
`handler_account.go`, `handler_alerts.go`, `handler_paper.go`,
`handler_pnl.go`, `handler_safety.go` exist but only declare empty
`<X>Handler` structs — no methods have been moved yet. Leaving as-is:
they don't cause build errors and future decomposition work can pick
them up. Not in scope for stabilize.
