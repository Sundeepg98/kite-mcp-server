# oauth/ Test Architecture — Progress

## Baseline
- 13 test files, coverage 92.4%

## Renames Performed
1. `push100_test.go` -> `handlers_coverage_test.go` (647 lines)
2. `ceil_test.go` -> `coverage_ceiling_test.go` (172 lines)
3. `cov_push_test.go` -> `stores_coverage_test.go` (88 lines)
4. `handlers_extra_test.go` -> `handlers_edge_test.go` (940 lines)

## Mock AdminUserStore Variants (7 total)
Noted for future consolidation — 7 variants across 3 files:
- `mockAdminUserStore` (google_sso_test.go)
- `mockAdminUserStoreFinal` (google_sso_test.go)
- `mockAdminUserStoreFinalWithError` (google_sso_test.go)
- `mockAdminUserStoreWithVerifyError` (gap_test.go)
- `mockAdminUserStoreWithPassword` (handlers_edge_test.go)
- `mockAdminUserStoreWithSetAdmin` (handlers_edge_test.go)
- `mockAdminUserStoreWithSetAdminError` (handlers_edge_test.go)

Each implements different method subsets. Consolidation into one configurable mock would require refactoring all test call sites. Deferred — low ROI for the risk.

## Verification
- `go test -count=1 -cover ./oauth/` — coverage 92.4% (matches baseline)
- All tests pass
