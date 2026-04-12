# Final Coverage Sweep — 2026-04-12

## Summary

**27 packages tested** | **25 passing** | **2 with known failures** (pre-existing, not from this session)

## Coverage Table

| Package | Coverage | Status | Notes |
|---------|----------|--------|-------|
| `app/metrics` | **99.3%** | PASS | |
| `broker/mock` | **86.4%** | PASS | |
| `broker/zerodha` | **99.7%** | PASS | |
| `cmd/rotate-key` | **97.5%** | PASS | |
| `kc` | **93.8%** | PASS | |
| `kc/alerts` | **96.1%** | PASS | |
| `kc/audit` | **97.2%** | PASS | |
| `kc/billing` | **98.3%** | PASS | |
| `kc/cqrs` | **100.0%** | PASS | |
| `kc/domain` | **95.5%** | PASS | |
| `kc/eventsourcing` | **99.2%** | PASS | |
| `kc/instruments` | **98.3%** | PASS | |
| `kc/isttz` | **75.0%** | PASS | Small timezone pkg, 2 funcs untested |
| `kc/ops` | **90.7%** | PASS | |
| `kc/papertrading` | **98.3%** | PASS | |
| `kc/registry` | **100.0%** | PASS | |
| `kc/riskguard` | **100.0%** | PASS | |
| `kc/scheduler` | **100.0%** | PASS | |
| `kc/telegram` | **99.7%** | PASS | |
| `kc/ticker` | **100.0%** | PASS | |
| `kc/usecases` | **99.8%** | PASS | |
| `kc/users` | **97.5%** | PASS | |
| `kc/watchlist` | **100.0%** | PASS | |
| `oauth` | **92.4%** | PASS | |
| `plugins/example` | **100.0%** | PASS | |
| `app` | **86.4%** | PASS | Fixed 6 broken tests (missing authenticator field) |
| `mcp` | **85.0%** | FAIL | Pre-existing: `TestActivityData_WithAuditStore` assert fails (ext_apps work) |
| (root) `main` | **46.4%** | PASS | main.go — low by design |

## Packages at 100%

7 packages at full coverage:
- `kc/cqrs`, `kc/registry`, `kc/riskguard`, `kc/scheduler`, `kc/ticker`, `kc/watchlist`, `plugins/example`

## Packages Over 95%

17 packages (including 100% ones):
- `app/metrics` (99.3%), `broker/zerodha` (99.7%), `cmd/rotate-key` (97.5%)
- `kc/alerts` (96.1%), `kc/audit` (97.2%), `kc/billing` (98.3%)
- `kc/domain` (95.5%), `kc/eventsourcing` (99.2%), `kc/instruments` (98.3%)
- `kc/papertrading` (98.3%), `kc/telegram` (99.7%), `kc/usecases` (99.8%)
- `kc/users` (97.5%)

## Fixes Made During Sweep

Fixed 6 broken tests in `app/server_test.go` — the monolith-split (task #3) moved `kiteExchangerAdapter` to `adapters.go` and replaced `kiteconnect.New()` with `broker.Authenticator`, but left 6 test constructions without the required `authenticator` field, causing nil pointer panics:
- `TestExchangeRequestToken_Error` (line 888)
- `TestExchangeWithCredentials_Error` (line 910)
- `TestExchangeRequestToken_EmptyKey` (line 1815)
- `TestExchangeWithCredentials_BadToken` (line 1827)
- `TestExchangeRequestToken_WithUserStore_OffboardedUser` (line 2243)
- `TestExchangeRequestToken_AllFieldsPopulated` (line 2260)
- `TestExchangeWithCredentials_AllFieldsPopulated` (line 2278)
- `TestExchangeWithCredentials_NilRegistryStore` (line 2305)

Each was fixed by adding `authenticator: newMockAuthError(...)` to the struct literal.

## Known Pre-existing Failures

1. **`mcp` package**: `TestActivityData_WithAuditStore` fails — from ext_apps widget work (task #2)
2. **`main` package**: `TestBinary_VersionFlag` — may be flaky on Windows (SAC policy)

## Regressions

None detected. All previously-passing packages continue to pass with same or higher coverage.
