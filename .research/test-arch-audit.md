# Test Architecture Audit

## Overview
- 174 test files, 7,037 test functions, 138K total lines
- 15 packages with tests

## 1. Test File Naming

### Coverage-push files (56 files — 32% of all test files)
Files named `ceil_test.go`, `push100_test.go`, `coverage_push_test.go`, `coverage_boost_test.go`, `gap_test.go`, `final_coverage_test.go`, `cov_push_test.go` etc. These are artifacts of incremental coverage campaigns.

**Issue**: 56 coverage-push files create naming confusion. Many contain tests that logically belong in the main test file for that source.

**Fix**: Consolidate — for each package, merge coverage-push tests into the primary test file (e.g., `store_test.go`, `engine_test.go`). Keep `ceil_test.go` as coverage ceiling documentation (14 files, useful).

### Well-named files
- `*_edge_test.go` (10 files) — clear purpose, edge case testing
- `*_factory_test.go` (4 files) — factory/injection point tests
- `*_integration_test.go` (2 files) — integration tests
- `*_property_test.go` (2 files) — property-based tests

## 2. Test Helpers — Duplication

### `testLogger()` duplicated in 7 packages
Each creates `slog.New(slog.NewTextHandler(io.Discard, nil))`:
- `app/app_test.go:22`
- `kc/instruments/manager_test.go:16`
- `kc/manager_test.go:72`
- `kc/scheduler/scheduler_test.go:11`
- `kc/telegram/bot_final_test.go:471`
- `kc/usecases/usecases_test.go:217`
- `oauth/testutil_test.go:128`

**Fix**: Create a shared `testutil` package with `testutil.Logger()`.

### `newTestStore()` duplicated in 4+ packages
Each package has its own `newTestStore` — acceptable since they create different store types, but the pattern is inconsistent (some use `t.Helper()`, some don't).

## 3. Test Patterns

### Testify usage: split
- 108 files use `testify/assert`
- 96 files use `testify/require`
- 65 files use only stdlib `testing`

**Issue**: Inconsistent — some files mix `assert` and `require` without clear rules. Some files use stdlib `t.Errorf` for assertions where `assert.Equal` would be clearer.

### Table-driven tests: underused
- Only 28 files use table-driven pattern (`tests := []struct`)
- Only 32 files use `t.Run()` subtests
- Many files repeat similar test structures that would be cleaner as table-driven

**Example**: `kc/telegram/commands_test.go` has ~10 `TestHandleBuy_*` functions that could be a single table-driven test.

### t.Parallel(): 47% adoption
- 82 of 174 files use `t.Parallel()`
- 14 packages have zero `t.Parallel()` usage
- Notable: `kc/telegram` (7 files, 0 parallel), `kc/riskguard` (4 files, 0 parallel)

## 4. Mock Patterns

### Consistent within packages, scattered across packages
- `kc/usecases`: 22 mock types — highest density, many single-method mocks
- `oauth`: 13 mock types
- `kc`: 8 mock types (root package)
- `kc/alerts`: 5 mock types

**Issue**: No shared mock infrastructure. `mockCredentialStore` defined separately in `kc/stores_test.go`, `kc/usecases/admin_coverage_test.go`, and `kc/usecases/cqrs_coverage_test.go`.

**Fix**: For interfaces used across 3+ packages, create `testutil/mocks.go` with standard mocks.

### fakeKiteAPI pattern — good
- `kc/telegram/handler_test.go` has `fakeKiteAPI` — well-structured httptest server
- `app/server_test.go` has `mockKiteAPIServer` — similar but simpler
- Both are good but not shared

## 5. Test Isolation

### No shared mutable state detected
All tests use local state. The main risk areas:
- `kc/telegram` tests don't use `t.Parallel()` — likely because `BotHandler` has internal mutexes
- Tests that use `t.Setenv()` correctly use the testing package's env management

## 6. Stale Coverage Files

### 56 coverage-push files
Most were created during coverage campaigns and contain tests of varying quality:
- Some are well-structured tests that just happen to target uncovered lines
- Some are minimal "exercise the function" tests with no real assertions
- Naming makes it hard to find tests for a specific function

### Worst offenders (by number of coverage files):
- `kc/ops`: 6 coverage files (coverage_100, coverage_final, coverage_max, coverage_push, ops_push100, ceil)
- `kc/papertrading`: 5 coverage files
- `kc/billing`: 4 coverage files
- `kc/alerts`: 4 coverage files

## 7. Duplicate Test Functions

`go vet ./...` passes clean — no within-package duplicates remain.

Cross-package duplicates exist (e.g., `TestFormatRupee` in both `kc/alerts` and `kc/telegram`) but these test different implementations and are valid.

## 8. Test Organization

### Oversized test files
- `app/server_test.go`: 5,900 lines — should be split by concern
- `mcp/tools_devmode_test.go`: 5,038 lines
- `oauth/handlers_test.go`: 4,141 lines
- `kc/ops/ops_push100_test.go`: 3,572 lines

### Recommended splits
- `app/server_test.go` → split into `app/oauth_handler_test.go`, `app/mcp_handler_test.go`, `app/admin_test.go`
- Large coverage-push files should be merged into their primary test files

## Summary of Recommendations

| Priority | Issue | Fix |
|----------|-------|-----|
| HIGH | 56 coverage-push files (32% of test files) | Merge into primary test files, keep ceil_test.go |
| MED | `testLogger()` in 7 packages | Shared `testutil.Logger()` |
| MED | 5,900-line server_test.go | Split by concern |
| LOW | t.Parallel in 47% of files | Add to remaining packages where safe |
| LOW | Table-driven in 16% of files | Refactor repetitive tests |
| LOW | Mixed testify/stdlib | Standardize on testify |
