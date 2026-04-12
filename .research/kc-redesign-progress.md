# kc/ Test Redesign Progress

## Baseline Coverage (recorded before changes)

| Package | Coverage | Notes |
|---------|----------|-------|
| kc/ | 93.8% | Root package |
| kc/alerts | 96.1% | |
| kc/audit | 97.2% | |
| kc/billing | 98.3% | |
| kc/cqrs | 100.0% | No agent files |
| kc/domain | 95.5% | No agent files |
| kc/eventsourcing | 99.2% | 1 ceil file |
| kc/instruments | 98.3% | |
| kc/isttz | 75.0% | No agent files |
| kc/ops | 90.7% | |
| kc/papertrading | 98.1% | |
| kc/registry | 100.0% | No agent files |
| kc/riskguard | 100.0% | No agent files |
| kc/scheduler | 100.0% | No agent files |
| kc/telegram | 99.7% | |
| kc/ticker | 100.0% | No agent files |
| kc/usecases | 99.8% | |
| kc/users | 96.9% | |
| kc/watchlist | 100.0% | No agent files |

## Agent-Named Files to Consolidate (40 files)

### kc/ (root) — 5 files
- coverage_ceiling_test.go → doc comment only, merge into helpers_test.go
- gap_test.go → real tests, merge by source file
- manager_coverage_test.go → real tests, merge into manager_test.go
- session_coverage_test.go → real tests, merge into session_test.go
- signing_coverage_test.go → real tests, merge into session_signing_test.go

### kc/ops/ — 4 files
- coverage_ceiling_test.go → doc comment only
- ops_coverage_test.go → real tests, merge into handler_test.go / dashboard tests
- admin_coverage_test.go → real tests, merge into ops_admin_test.go
- factory_test.go → real tests (factory injection pattern), keep or merge

### kc/alerts/ — 5 files
- coverage_ceiling_test.go → doc comment only
- alerts_coverage_test.go → real tests, merge into store_test.go / evaluator_test.go
- briefing_coverage_test.go → real tests, merge into briefing_test.go
- briefing_factory_test.go → real tests, merge into briefing_test.go
- evaluator_coverage_test.go → real tests, merge into evaluator_test.go

### kc/audit/ — 3 files
- ceil_test.go → doc comment only
- store_final_test.go → real tests, merge into store_test.go
- store_push100_test.go → real tests, merge into store_test.go

### kc/billing/ — 4 files
- ceil_test.go → doc comment only
- billing_final_test.go → real tests, merge into billing_test.go
- cov_push_test.go → real tests, merge into billing_test.go
- final_coverage_test.go → real tests, merge into billing_test.go

### kc/telegram/ — 4 files
- ceil_test.go → doc comment only
- push100_test.go → real tests, merge into handler_test.go / commands_test.go
- bot_final_test.go → real tests, merge into handler_test.go
- trading_factory_test.go → real tests, keep or merge

### kc/instruments/ — 3 files
- ceil_test.go → doc comment only
- push100_test.go → real tests, merge into manager_test.go
- manager_final_test.go → real tests, merge into manager_test.go

### kc/papertrading/ — 5 files
- ceil_test.go → doc comment only
- push100_test.go → real tests, merge into engine_test.go
- gap_test.go → real tests, merge into engine_test.go
- final_push_test.go → real tests, merge into engine_test.go
- engine_extra_test.go → real tests, merge into engine_test.go

### kc/users/ — 3 files
- ceil_test.go → real tests + docs, merge into store_test.go
- push100_test.go → real tests, merge into store_test.go
- final_coverage_test.go → real tests, merge into store_test.go

### kc/eventsourcing/ — 1 file
- ceil_test.go → doc comment only

### kc/usecases/ — 3 files
- admin_coverage_test.go → real tests, merge into usecases_test.go
- cqrs_coverage_test.go → real tests, merge into usecases_test.go
- observability_coverage_test.go → real tests, merge into usecases_test.go

## Plan

### Phase 1: Create helpers_test.go per package
Extract shared helpers/mocks from agent files into helpers_test.go.

### Phase 2: Merge test functions
Move test functions from agent files into source-matching test files.

### Phase 3: Move ceiling docs
Convert ceiling docs to comments at bottom of helpers_test.go.

### Phase 4: Delete agent files
Remove all 40 agent-named files.

### Phase 5: Verify
Run tests, check coverage >= baseline, go vet clean.

## Status: WAITING for Task 1 (testutil/) to complete
