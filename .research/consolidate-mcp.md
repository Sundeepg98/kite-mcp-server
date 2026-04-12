# Consolidate mcp/ Test Files — Progress

## Baseline
- 32 test files, coverage 85.1% (with pre-existing ext_apps failures)

## Renames Performed
1. `tools_test_helpers_test.go` -> `helpers_test.go` (clarity)
2. `tools_push100_test.go` -> `tools_handlers_mock_test.go` (describes what it tests)
3. `tools_coverage_push_test.go` -> `tools_devmode_extra_test.go` (describes what it tests)
4. `ceil_test.go` -> `coverage_ceiling_test.go` (clarity)

## Updated Header Comment
- `tools_handlers_mock_test.go` header updated to remove push100 reference

## Why Not Full Merge
The push100 (65 funcs) and coverage_push (190+ funcs) files are too large to safely merge into other already-large files (tools_devmode_test.go is 5038 lines, tools_validation_test.go is 3380 lines). Merging would create 7000-8000 line test files which would be worse than the current state. Renaming to meaningful names is the practical fix.

## Verification
- `go build ./mcp/` — clean
- `go test -count=1 -cover ./mcp/` — coverage 85.1% (matches baseline exactly)
- Same pre-existing failures from ext_apps work (not caused by renames)

## File Count
Still 32 test files (renames, not deletions). 4 legacy-named files renamed to meaningful names.
