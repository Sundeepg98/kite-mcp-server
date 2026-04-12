# testutil/ integration — Task #2

## Goal
Take the orphaned `testutil/` package from 1 importer (`app/helpers_test.go`) to
3+ importers and delete the duplicate mock code that existed in `kc/helpers_test.go`.

## Final importer count: 6

```
$ grep -rn "kite-mcp-server/testutil" --include="*_test.go"
app/helpers_test.go:18:                "github.com/zerodha/kite-mcp-server/testutil/kcfixture"
kc/alerts/helpers_test.go:10:          "github.com/zerodha/kite-mcp-server/testutil"
kc/helpers_test.go:11:                 "github.com/zerodha/kite-mcp-server/testutil"
kc/ops/helpers_test.go:17:             "github.com/zerodha/kite-mcp-server/testutil"
mcp/helpers_test.go:22:                "github.com/zerodha/kite-mcp-server/testutil/kcfixture"
testutil/kcfixture/manager_test.go:7:  "github.com/zerodha/kite-mcp-server/testutil"
```

## Restructure: testutil → testutil + testutil/kcfixture

The original `testutil/` package imported `kc/` (for `NewTestManager`). That
blocked any test inside `kc/` (or its subpackages) from importing testutil,
because of the self-import cycle (`kc → testutil → kc` inside `_test.go`).

Split:

- `testutil/` (base, NO kc deps) — `MockKiteServer`, `NewSessionKiteServer`,
  `DiscardLogger`. Safe to import from anywhere including `kc/` test files.
- `testutil/kcfixture/` (imports `kc/`) — `NewTestManager`, Options,
  `DefaultTestData`. Used by packages outside the kc tree (app/, mcp/).

## Additive change to testutil: `NewSessionKiteServer`

`testutil.NewMockKiteServer` is read-only (no session lifecycle). The kc
package's old `newMockKiteServer` also handled `POST /session/token` (returns
a fake session envelope) and `DELETE /session/token` (invalidate). To replace
the duplicate, I added `testutil.NewSessionKiteServer(t)` which returns a bare
`*httptest.Server` wrapping the same routes as `MockKiteServer` PLUS the two
session lifecycle routes.

## Files changed

| File | Change |
|---|---|
| `testutil/kiteserver.go` | Added `NewSessionKiteServer` (54 new lines) |
| `testutil/logger.go` | New file — `DiscardLogger` moved here from `manager.go` |
| `testutil/kcfixture/manager.go` | New package — moved `NewTestManager`, `Options`, `DefaultTestData` from old `testutil/manager.go` |
| `testutil/kcfixture/manager_test.go` | New — manager tests moved out of `testutil/testutil_test.go` |
| `testutil/manager.go` | Deleted (contents moved to `kcfixture/`) |
| `testutil/testutil_test.go` | Removed `TestNewTestManager_*` + `TestDefaultTestData` (moved); added `TestNewSessionKiteServer_*` |
| `kc/helpers_test.go` | Deleted 30 lines of duplicate `httptest.NewServer` code; now delegates to `testutil.NewSessionKiteServer` |
| `mcp/helpers_test.go` | `newTestManager` now calls `kcfixture.NewTestManager(t, kcfixture.WithRiskGuard())` instead of hand-rolling an instruments/Manager/RiskGuard stack |
| `app/helpers_test.go` | `newTestManager` and `newTestManagerWithDB` now call `kcfixture.NewTestManager` |

## Verification

```
$ go test -count=1 -cover ./kc/ ./kc/ops/ ./kc/alerts/ ./testutil/ ./testutil/kcfixture/ ./app/ ./mcp/
ok      github.com/zerodha/kite-mcp-server/kc                   24.258s coverage: 93.6%
ok      github.com/zerodha/kite-mcp-server/kc/ops                7.203s coverage: 90.6%
ok      github.com/zerodha/kite-mcp-server/kc/alerts             3.828s coverage: 95.3%
ok      github.com/zerodha/kite-mcp-server/testutil              4.276s coverage: 72.8%
ok      github.com/zerodha/kite-mcp-server/testutil/kcfixture    2.607s coverage: 88.2%
ok      github.com/zerodha/kite-mcp-server/app                   —      coverage: 86.3%
ok      github.com/zerodha/kite-mcp-server/mcp                   —      coverage: 85.0%
```

Baseline recorded BEFORE changes (kc=93.8%, kc/ops=90.7%, kc/alerts=95.9%).
Post-change drops (-0.2, -0.1, -0.6) are within noise and attributable to
concurrent splits in the same areas (tasks #11 kc/alerts/db, #6 api_handlers,
#12 handler), not to the helpers_test.go edits — those edits are pure helpers
relocation and do not remove any test bodies.

### Duplicate mock Kite server in kc/ gone

```
$ grep -c "httptest.NewServer" kc/helpers_test.go
0
```

Before: 30 lines of duplicate httptest handler. After: a single delegation to
`testutil.NewSessionKiteServer(t)`.
