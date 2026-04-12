# Test Architecture Audit — Final Report

**Date**: 2026-04-12 (re-audit after refactoring)
**Stats**: 177 test files, ~138K total lines

---

## 1. Legacy Naming Conventions (35 files flagged)

### push100/push_100/final_push files (16 files)
These names reflect a coverage sprint, not what they test:
- `app/app_push100_test.go`
- `app/push100_extra_test.go`
- `kc/alerts/push_100_test.go`
- `kc/audit/store_push100_test.go`
- `kc/instruments/push100_test.go`
- `kc/ops/ops_push100_test.go`
- `kc/papertrading/final_push_test.go`
- `kc/papertrading/push100_test.go`
- `kc/telegram/push100_test.go`
- `kc/users/push100_test.go`
- `mcp/tools_push100_test.go`
- `mcp/tools_coverage_push_test.go`
- `oauth/push100_test.go`

**Fix**: Rename to describe what's tested or merge into primary test file.

### coverage/final_coverage files (7 files)
- `app/app_coverage_test.go`
- `kc/alerts/final_coverage_test.go`
- `kc/billing/final_coverage_test.go`
- `kc/session_signing_coverage_test.go`
- `kc/usecases/admin_coverage_test.go`
- `kc/usecases/cqrs_coverage_test.go`
- `kc/usecases/observability_coverage_test.go`
- `kc/users/final_coverage_test.go`

**Fix**: Rename to describe feature tested or merge into primary test files.

### ceil_test.go files (14 files)
Present in almost every package:
- `app/ceil_test.go`
- `app/metrics/ceil_test.go`
- `kc/ceil_test.go`
- `kc/alerts/ceil_test.go`
- `kc/audit/ceil_test.go`
- `kc/billing/ceil_test.go`
- `kc/eventsourcing/ceil_test.go`
- `kc/instruments/ceil_test.go`
- `kc/ops/ceil_test.go`
- `kc/papertrading/ceil_test.go`
- `kc/telegram/ceil_test.go`
- `kc/users/ceil_test.go`
- `mcp/ceil_test.go`
- `oauth/ceil_test.go`

**Fix**: "ceil" is unclear naming. Rename or merge into primary test files.

**Total legacy-named files**: 35 out of 177 (20%)

---

## 2. Duplicate Test Function Names

**None found within any package.** Clean — no duplicates.

34 duplicate function names exist *across* packages (expected in Go, since test funcs are package-scoped):
- `TestCancelOrder`, `TestCreateWatchlist_EmptyName`, `TestDeleteMyAccount_Success`, `TestFormatRupee`, `TestGetMargins`, `TestModifyOrder`, `TestPlaceMarketOrder`, etc.

**Verdict**: No action needed — cross-package duplicates are normal in Go.

---

## 3. Duplicate Helpers Across Test Files

**No duplicate helpers within any single package.** Clean.

Cross-package duplicates (expected, acceptable):
- `testLogger()` in 7 packages — each creates package-local `slog.Logger`
- `newTestManager()` in 4 packages — different return types
- `newTestStore()` in 4 packages — different store types

**Verdict**: No fix needed. Go test helpers are package-scoped by design.

---

## 4. Test File / Source File Alignment

Most test files don't match a specific source file — they're named for the coverage sprint that created them:
- 35+ test files have no corresponding source file (push100, ceil, coverage, extra, final patterns)
- This is the main organizational debt

Packages with highest test-to-source file ratios:
| Package | Source files | Test files | Ratio |
|---------|-------------|------------|-------|
| `kc/telegram` | 5 | 9 | 1.8x |
| `kc/papertrading` | 5 | 10 | 2.0x |
| `app` | 8 | 15 | 1.9x |
| `oauth` | 8 | 14 | 1.8x |

High ratios are driven by legacy-named supplemental test files.

---

## 5. Test Files Over 2000 Lines (16 files)

| File | Lines | Notes |
|------|-------|-------|
| `app/server_test.go` | 5875 | Largest — server lifecycle, split by concern |
| `mcp/tools_devmode_test.go` | 5038 | Devmode tool tests |
| `oauth/handlers_test.go` | 4141 | OAuth handler tests |
| `kc/ops/ops_push100_test.go` | 3572 | Legacy name + oversized |
| `mcp/tools_validation_test.go` | 3380 | Validation tests |
| `kc/alerts/db_test.go` | 3371 | Database alert tests |
| `mcp/tools_pure_test.go` | 3115 | Pure function tests |
| `kc/ops/admin_extra_test.go` | 2807 | Legacy name + oversized |
| `kc/billing/billing_test.go` | 2727 | Billing tests |
| `app/app_coverage_test.go` | 2608 | Legacy name + oversized |
| `kc/telegram/handler_test.go` | 2567 | Handler tests |
| `mcp/tools_coverage_push_test.go` | 2489 | Legacy name + oversized |
| `kc/manager_test.go` | 2436 | Manager tests |
| `oauth/google_sso_test.go` | 2308 | SSO tests |
| `mcp/tool_handlers_test.go` | 2225 | Tool handler tests |
| `kc/usecases/usecases_test.go` | 2204 | Use case tests |

5 of 16 have legacy names that compound the issue.

---

## 6. Mock Consistency

**Mocks are per-package, not shared.** Each package defines its own mock types:

| Package | Mock types | Notes |
|---------|-----------|-------|
| `kc/usecases` | 20 | Most mock-heavy — tests all use case deps |
| `oauth` | 13 | Many mockAdminUserStore variants |
| `kc` | 8 | Manager dependency mocks |
| `kc/alerts` | 5 | Broker/token/credential mocks |
| `kc/cqrs` | 3 | Command/query handler mocks |
| `kc/telegram` | 3 | HTTP/manager/lookup mocks |
| `kc/ticker` | 3 | Callback/connection mocks |
| `mcp` | 3 | Broker/session mocks |
| `app` | 2 | Auth/bot mocks |
| `kc/ops` | 2 | Billing store/response writer |
| Others | 1 each | Minimal, focused |

`broker/mock/` package provides reusable `MockClient` — good shared pattern.

**Verdict**: Acceptable Go convention. Most mocks are interface-specific, small, and scoped to their test file. The `oauth` package has some redundancy (4 variants of `mockAdminUserStore`) that could be consolidated.

---

## 7. t.Parallel() Usage

- **82 files** use `t.Parallel()` (46% of test files)
- **77 files** with test functions do NOT use `t.Parallel()`

Files missing `t.Parallel()` include:
- All legacy-named files (push100, ceil, coverage, extra)
- Most SQLite-dependent tests (audit, billing, watchlist, registry, users)
- Broker client tests (shared state)
- Manager tests (shared Manager instance)

**Verdict**: Many tests use SQLite or shared mutable state, making `t.Parallel()` unsafe within the package. The missing parallelism is largely appropriate. Adding it blindly would cause flaky tests. Only add where tests are truly independent (pure function tests, struct construction tests).

Safe candidates for adding `t.Parallel()`:
- `kc/cqrs/cqrs_test.go` (serialization tests, no shared state)
- `kc/cqrs/bus_test.go` (bus creation tests)
- `kc/domain/events_test.go` (pure struct tests)
- `kc/domain/spec_test.go` (pure validation tests)
- `kc/isttz/isttz_test.go` (timezone conversion, stateless)
- `mcp/indicators_property_test.go` (pure math tests)
- `mcp/options_greeks_property_test.go` (pure math tests)

---

## 8. _extra_ and _edge_ test files (18 files)

| Pattern | Count | Files |
|---------|-------|-------|
| `*_edge_test.go` | 12 | broker/mock, kc/audit, kc/domain, kc/eventsourcing, kc/instruments, kc/manager, kc/ops, kc/papertrading, kc/riskguard, kc/ticker (2), mcp |
| `*_extra_test.go` | 6 | app, kc/manager, kc/ops, kc/papertrading, kc/session, oauth |

**Edge files**: Generally well-named — test boundary conditions. Acceptable.
**Extra files**: Legacy naming from coverage sprints. Should merge into primary or edge test files.

---

## Summary

| Issue | Count | Severity | Recommendation |
|-------|-------|----------|----------------|
| Legacy-named files (push100, coverage, ceil, extra) | 35 | **Medium** | Rename or consolidate |
| Files over 2000 lines | 16 | **Medium** | Split by concern |
| Duplicate test function names (within package) | 0 | None | Clean |
| Duplicate helpers (within package) | 0 | None | Clean |
| Mock scattering | ~64 types | **Low** | Acceptable per Go convention |
| Missing t.Parallel() | 77 files | **Low** | Largely appropriate for stateful tests |
| _extra_ files (unclear naming) | 6 | **Low** | Merge into primary test files |

### Priority Actions

1. **Rename/merge 14 ceil_test.go files** — most confusing naming, present everywhere
2. **Rename/merge 16 push100 files** — sprint artifact naming
3. **Rename/merge 7 coverage/final_coverage files** — sprint artifact naming
4. **Split 5 files over 3500 lines**: `server_test.go` (5875), `tools_devmode_test.go` (5038), `handlers_test.go` (4141), `ops_push100_test.go` (3572), `tools_validation_test.go` (3380)
5. **Consolidate oauth mock variants** — 4 `mockAdminUserStore*` types could be 1 configurable mock
6. **Add t.Parallel() to 7 safe candidates** — pure function test files listed above
