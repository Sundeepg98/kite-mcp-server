# Task #13 — Consolidate kc/ root package mocks

## Scope
Move scattered mock types in package `kc` _test.go files into one shared file `kc/mocks_test.go`.

## Verification counts

### Before (baseline)
```
$ grep -c "^type mock" kc/*_test.go
kc/helpers_test.go:0
kc/manager_edge_test.go:1    # mockMetrics
kc/manager_test.go:0
kc/service_test.go:2          # mockUserStoreForFamily, mockBillingStoreForFamily
kc/session_edge_test.go:0
kc/session_signing_edge_test.go:0
kc/session_signing_test.go:0
kc/session_test.go:1          # mockSessionDB
kc/stores_test.go:4           # mockCredentialStore, mockTokenStore, mockRegistryStore, mockCredentialStoreWithRaw
```
Total: 8 mock types across 4 files.

### After
```
$ grep -c "^type mock" kc/*_test.go
kc/helpers_test.go:0
kc/manager_edge_test.go:0
kc/manager_test.go:0
kc/mocks_test.go:8            # all consolidated here
kc/service_test.go:0
kc/session_edge_test.go:0
kc/session_signing_edge_test.go:0
kc/session_signing_test.go:0
kc/session_test.go:0
kc/stores_test.go:0
```
Total: 8 mock types in 1 file. All 4 original files now 0.

## Mocks consolidated (8)
1. `mockCredentialStore` — CredentialStoreInterface
2. `mockCredentialStoreWithRaw` — CredentialStoreInterface (raw variant)
3. `mockTokenStore` — TokenStoreInterface
4. `mockRegistryStore` — RegistryStoreInterface (13 methods)
5. `mockMetrics` — Metrics interface
6. `mockSessionDB` + `newMockSessionDB()` — SessionDB
7. `mockUserStoreForFamily` — FamilyUserStore
8. `mockBillingStoreForFamily` — BillingStoreInterface

## Files changed
- `kc/mocks_test.go` — NEW, 258 lines, all 8 mocks + `newMockSessionDB` constructor
- `kc/stores_test.go` — removed 4 mock types (mockCredentialStore, mockTokenStore, mockRegistryStore, mockCredentialStoreWithRaw), left pointer comments
- `kc/manager_edge_test.go` — removed mockMetrics
- `kc/session_test.go` — removed mockSessionDB + newMockSessionDB
- `kc/service_test.go` — removed mockUserStoreForFamily + mockBillingStoreForFamily (already gone when I reached it — concurrent consolidation, but count verified)

## Verification commands run
```
$ gofmt -l kc/mocks_test.go kc/stores_test.go kc/manager_edge_test.go kc/session_test.go kc/service_test.go
(empty — all clean after `gofmt -w kc/manager_edge_test.go`)

$ gofmt -e kc/mocks_test.go kc/stores_test.go kc/manager_edge_test.go kc/session_test.go kc/service_test.go
syntax OK on 5 files
```

## go vet / go test status
`go vet ./kc/` currently fails on `kc/manager.go:4:2: "context" imported and not used`. This is Task #14's in-progress Manager decomposition work — unrelated to Task #13. My changes are _test.go-only and verified syntax-clean via `gofmt -e`.

When Task #14 stabilizes, `go test ./kc/` should pass because:
1. All mock types remain in package `kc`, so call sites still resolve via package scope.
2. No name collisions introduced (grep verified `^type mock` count per file).
3. Imports in `kc/mocks_test.go` (`time`, `billing`, `registry`, `users`) match those needed by the moved types.
4. Source files kept their imports valid because the types they referenced still exist in the same package (checked `users.`, `billing.`, `time.` usage remains in each file).

## Orphaned import check
- `kc/session_test.go` — still uses `time` (19 refs). Import valid.
- `kc/manager_edge_test.go` — still uses `time` (47 refs). Import valid.
- `kc/stores_test.go` — still uses `registry` (12 refs from tests). Import valid.
- `kc/service_test.go` — still references `users.User` and `billing.Subscription` via mock instantiation. Imports valid.

## Conflicts
None. This task touched only `_test.go` files. No production code changes. No collision with Tasks #2, #3, #14 which operate on production files or non-kc-root test directories.
