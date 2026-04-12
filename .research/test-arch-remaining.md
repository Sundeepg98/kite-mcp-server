# app/ + kc/ + kc/alerts/ Test Architecture — Progress

## Baselines
- `app/` — 86.5% (13 files)
- `kc/` — 93.8% (11 files)
- `kc/alerts/` — 96.1% (12 files)

## app/ Renames (4 files)
1. `app_coverage_test.go` -> `server_coverage_test.go` (2608 lines)
2. `app_push100_test.go` -> `oauth_coverage_test.go` (995 lines)
3. `push100_extra_test.go` -> `adapters_coverage_test.go` (344 lines)
4. `ceil_test.go` -> `coverage_ceiling_test.go` (138 lines)

Verification: coverage 86.5% — matches baseline.

## kc/ Renames (4 files)
1. `manager_extra_test.go` -> `manager_coverage_test.go` (1489 lines)
2. `session_extra_test.go` -> `session_coverage_test.go` (1303 lines)
3. `session_signing_coverage_test.go` -> `signing_coverage_test.go` (308 lines)
4. `ceil_test.go` -> `coverage_ceiling_test.go` (182 lines)

Verification: SAC intermittently blocks test binary (Windows policy). Package compiled clean. Coverage was 93.8% in earlier run this session.

## kc/alerts/ Renames (4 files)
1. `push_100_test.go` -> `alerts_coverage_test.go` (479 lines)
2. `final_coverage_test.go` -> `briefing_coverage_test.go` (303 lines)
3. `cov_push_test.go` -> `evaluator_coverage_test.go` (75 lines)
4. `ceil_test.go` -> `coverage_ceiling_test.go` (158 lines)

Verification: coverage 96.1% — matches baseline.

## Also Fixed
- 8 broken tests in `app/server_test.go` — added missing `authenticator` field (from monolith split)
