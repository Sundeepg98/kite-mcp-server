# Split kc/ops/api_handlers.go — Task #6 Progress

## Scope
Split `kc/ops/api_handlers.go` (1892 lines) into focused files. No single file
in `kc/ops/api_*.go` should exceed 600 lines after the split.

## Before
```
1892 kc/ops/api_handlers.go
```
A single file mixing activity audit + portfolio + holdings + sector exposure +
tax analysis + alerts + P&L chart + orders + order attribution + paper trading
+ account self-service + status health check.

## After

| file                      | lines | responsibilities |
| ------------------------- | ----- | ---------------- |
| `api_activity.go`         |  197  | activityAPI, activityExport, activityStreamSSE (audit feed + CSV/JSON export + SSE) |
| `api_portfolio.go`        |  418  | marketIndices, portfolio, buildPortfolioResponse, sectorExposureAPI, computeDashboardSectorExposure, dashboardNormalizeSymbol, dashboardStockSectors + portfolio/sector types |
| `api_tax.go`              |  172  | taxAnalysisAPI, computeTaxAnalysis + tax types |
| `api_alerts.go`           |  330  | alerts, alertsEnrichedAPI, pnlChartAPI + alert/pnl-chart types + alertCopy |
| `api_orders.go`           |  340  | ordersAPI, orderAttributionAPI, formatDuration + order/attribution types |
| `api_paper.go`            |  131  | paperStatus, paperHoldings, paperPositions, paperOrders, paperReset |
| `api_handlers.go`         |  287  | status, safetyStatus, selfDeleteAccount, selfManageCredentials, maskKey + status types (retained as the account/system file) |

Total production lines across the 7 files: **1875** (slightly less than the
original 1892 because per-file imports and the existing block-comment section
separators from the monolith are no longer needed).

Test file `api_handlers_test.go` (1689 lines) is unchanged — all its referenced
symbols (`orderEntry`, `holdingItem`, etc.) remain in the same `ops` package,
just hosted in more focused files.

## Verification
```
$ wc -l kc/ops/api_*.go | grep -v _test
 197 kc/ops/api_activity.go
 330 kc/ops/api_alerts.go
 287 kc/ops/api_handlers.go
 340 kc/ops/api_orders.go
 131 kc/ops/api_paper.go
 418 kc/ops/api_portfolio.go
 172 kc/ops/api_tax.go
```
Max is 418 — well under the 600-line ceiling.

- `go build ./kc/ops/` → clean
- `go vet ./kc/ops/` → clean
- `gofmt -l` on all 7 new files → clean
- No duplicate type/func/var declarations across the new files (verified by
  sort/uniq on exported declarations).
- Test binary compile blocked downstream by a transient duplicate-method issue
  in `kc/alerts/db.go` vs `kc/alerts/crypto.go` from the concurrent task #11
  split — not introduced by this change; `kc/ops` itself is clean.

## Files touched
- `kc/ops/api_handlers.go` (shrunk from 1892 → 287 lines; kept account/status/safety)
- `kc/ops/api_activity.go` (new)
- `kc/ops/api_portfolio.go` (new)
- `kc/ops/api_tax.go` (new)
- `kc/ops/api_alerts.go` (new)
- `kc/ops/api_orders.go` (new)
- `kc/ops/api_paper.go` (new)
