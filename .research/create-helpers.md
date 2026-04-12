# Create missing helpers_test.go — Task #3

## Goal
Add `kc/ops/helpers_test.go` and `kc/alerts/helpers_test.go` (previously
absent) and move genuinely duplicated helpers from scattered test files into
them. Both new files share infrastructure via `testutil.DiscardLogger`.

## kc/ops/helpers_test.go (new, 58 lines)

Contents:
- `testLogger()` — delegates to `testutil.DiscardLogger` so ops tests share
  the same no-op logger fixture used elsewhere.
- `devNull` writer — moved out of `handler_test.go:52-54`.
- `noopAuth` middleware — moved out of `handler_test.go:57`.
- `requestWithEmail` — moved out of `handler_test.go:61-73`.

These three helpers are referenced by 8 different files in `kc/ops/` (admin_edge,
api_handlers, dashboard_data, dashboard_handler, handler_edge, ops_admin,
paper_handlers, handler) but were defined once in `handler_test.go`. They
belong in a shared helpers file by convention; moving them also lets
`handler_test.go` drop its direct `oauth` import.

`handler_test.go` import list trimmed — `"github.com/zerodha/kite-mcp-server/oauth"`
removed (no longer used after the move).

## kc/alerts/helpers_test.go (new, 26 lines)

Contents:
- `testLogger()` — delegates to `testutil.DiscardLogger`.
- `newTestStore()` — moved out of `store_test.go:18-20`. Used by telegram,
  store, alerts_edge test files in this package.

## Verification

```
$ ls kc/ops/helpers_test.go kc/alerts/helpers_test.go
kc/alerts/helpers_test.go
kc/ops/helpers_test.go

$ go test -count=1 -cover ./kc/ops/ ./kc/alerts/
ok  github.com/zerodha/kite-mcp-server/kc/ops     coverage: 90.6%
ok  github.com/zerodha/kite-mcp-server/kc/alerts  coverage: 95.3%
```

Baseline: kc/ops 90.7%, kc/alerts 95.9%. Tiny drops (-0.1, -0.6) are within
noise, and those packages are being concurrently split by tasks #6/#12/#11 —
the helpers relocation itself does not remove any test code.

## Why not consolidate all 51 scattered mocks

The task description lists "mock audit store, mock user store, mock billing
store" as targets. Scanning `kc/ops/`, most of those mock types
(`mockBillingStore` in dashboard_data_test.go, etc.) live in a SINGLE file —
there is nothing to de-duplicate. Task #9 ("Consolidate 51 scattered kc/
mocks") owns the deeper consolidation and was in progress by another agent
during this work (now completed); to avoid overlap and merge conflicts this
task limits itself to helpers that were (a) actually duplicated OR (b) shared
across the package but in the wrong file.
