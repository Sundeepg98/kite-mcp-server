# Path A.11 Pick — kc/alerts (billing-chain step 1)

**Date**: 2026-05-10
**Selected**: `kc/alerts` -> `algo2go/kite-mcp-alerts`
**Master HEAD at dispatch**: `6a8750b` (= production v235 + Path A.10 kc/domain external)

## Decision: kc/alerts (single promotion, billing-chain step 1)

Per orchestrator dispatch authorizing the kc/billing unblocking
chain (alerts -> users -> oauth -> billing). This is the **12th**
algo2go module promotion and **the first step** in the chain.

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer files | Tests |
|---|---:|---:|---|---:|---|
| **kc/alerts** | 38 | 15486 | 5 deps (broker, domain, isttz, logger, money — ALL EXTERNAL) + testutil (test-only, in-tree) | 155 (951 occurrences) | yes |

### Pick rationale

- **All production deps are external**: broker, domain, isttz, logger,
  money (via domain transitive) — all at v0.1.0 on algo2go. kc/alerts's
  go.mod requires resolve cleanly via GOPROXY.
- **Strategic value**: kc/alerts Phase B unblocks kc/users (depends on
  alerts) for Path A.12. After kc/users: oauth single-feasible. After
  oauth: kc/billing single-feasible. Billing chain remaining: 3
  dispatches × ~2-4h.

### testutil handling

kc/alerts has 1 problematic dep — `github.com/zerodha/kite-mcp-server/testutil`
imported by 2 _test.go files only:
- `helpers_test.go` (26 LOC) — uses `testutil.DiscardLogger()`
- `briefing_injection_test.go` (~155 LOC) — uses `testutil.MockKiteServer`

testutil is workspace-only (16+ internal deps + cyclic root, deferred
indefinitely per future-candidates analysis). Standard kc/money halt
scenario: upstream require would be unfetchable.

**Resolution**: surgical strip during rewrite, NOT halt:
1. **helpers_test.go**: inline-replace `testutil.DiscardLogger()` with
   stdlib `slog.New(slog.NewTextHandler(io.Discard, nil))`. 26 LOC
   → 26 LOC, zero functional change. **Keeps 9 dependent test files
   compiling** (alerts_edge_test.go, anomaly_notifier_test.go,
   briefing_test.go, composite_test.go, db_test.go, store_test.go,
   telegram_test.go all use `newTestStore()` + `testLogger()` from
   helpers_test.go).
2. **briefing_injection_test.go**: strip entirely. Uses MockKiteServer
   fixture that is harder to inline. One test file lost in upstream.
   Documented in upstream README. Test still runs in consumer's
   workspace mode where testutil resolves.

Standalone build PASS. Standalone tests PASS (~30+ test functions
run in upstream module's `go test ./...`).

This is NOT a kc/billing-class halt — it's a 2-file mechanical fix
that preserves >95% of test surface in upstream.

### Why not halt like kc/billing?

kc/billing halt was structural: 3 unpublished kc/* deps WITH heavy
type-identity exposure. kc/alerts has 1 unpublished dep (testutil)
with TEST-ONLY usage in 2 files. Mechanical strip + inline-replace
fully resolves it. No production code is affected; no type-identity
crosses module boundaries via testutil (all helpers are intra-package).

## Stop-rule observations

- ~3-4h budget — fits comfortably
- No second halt during this dispatch
- testutil-strip pattern documented for future use (other modules
  may need similar handling: kc/users? oauth? billing?)

## Forward-looking impact

After kc/alerts ships, the future-candidates table updates:

| Module | Status after kc/alerts external |
|---|---|
| **kc/users** | **Single-promotion candidate** (only blocking dep was kc/alerts) |
| oauth | Still needs kc/users external |
| kc/billing | Still needs oauth + alerts (alerts now external) |

Path A.12 most viable: kc/users (single-leaf after kc/alerts external).

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators DONE,
i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger DONE,
templates DONE, aop DONE, domain DONE, **alerts IN FLIGHT (billing
chain step 1)**.
