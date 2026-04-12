# mcp/ Test Redesign Progress

## Baseline
- Coverage: 85.1% (85.2% after consolidation)
- Pre-existing failures: 7 tests in tools_ext_apps_test.go (unchanged)
- Files: 32 test files

## Completed

### 1. helpers_test.go consolidation
All shared test helpers now live in `mcp/helpers_test.go`:
- `mockSession` struct
- `callToolAdmin`, `callToolDevMode`, `callToolWithSession`, `callToolWithManager`, `callToolNFODevMode`
- `newTestManager`, `newDevModeManager`, `newRichDevModeManager`, `newFullDevModeManager`, `newNFODevModeManager`
- `resultText`, `assertResultContains`, `assertResultNotContains`
- `newTestAuditStore`

### 2. File merges
- `tools_devmode_extra_test.go` (2489 lines) -> merged into `tools_devmode_test.go`
- `tools_handlers_mock_test.go` (1094 lines) -> merged into `tool_handlers_test.go`
- `coverage_ceiling_test.go` (102 lines) -> condensed comment in helpers_test.go, file deleted

### 3. Import cleanup
- Removed unused imports from tools_devmode_test.go, tool_handlers_test.go, tools_ext_apps_test.go

## Result
- Files: 29 test files (3 removed)
- Coverage: 85.2% (>= baseline 85.1%)
- `go vet ./mcp/` clean
- Same 7 pre-existing test failures (tools_ext_apps_test.go)
