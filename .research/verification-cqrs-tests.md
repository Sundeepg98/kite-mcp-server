# CQRS & Test Architecture Verification Report

## CLAIM 1: 8 MCP Tools Bypass CQRS

**STATUS: PARTIAL** — Found 4 confirmed bypasses, not 8.

### Confirmed Bypasses (Direct Broker Calls Outside Use Cases)

| File | Line | Code | Context |
|------|------|------|---------|
| mcp/common.go | 147 | `session.Broker.GetProfile()` | Middleware (WithTokenRefresh) — checks token expiry |
| mcp/post_tools.go | 193 | `session.Broker.GetOrderHistory(orderID)` | Post-execution enrichment in PlaceOrderTool |
| mcp/trailing_tools.go | 117 | `session.Broker.GetOrderHistory(orderID)` | Fallback data fetch in SetTrailingStopTool |
| mcp/trailing_tools.go | 131 | `session.Broker.GetLTP(instrumentID)` | Fallback data fetch in SetTrailingStopTool |

**Analysis:**
- Lines 68-70, 143-145, 166-168, 300-302, 369 in exit_tools.go and post_tools.go are NOT bypasses — they pass `handler.manager` to use case constructors, routing through the CQRS layer.
- Kite API type-assertions (e.g., `session.Broker.(broker.NativeAlertCapable)`) are not direct calls; they route through use cases (verified in native_alert_tools.go lines 187, 233, 403).

**Total CQRS Bypasses: 4** (not 8)

---

## CLAIM 2: Incomplete kc/helpers_test.go vs Substantial mcp/helpers_test.go

**STATUS: TRUE**

### Line Counts & Function Counts

| File | Lines | Functions |
|------|-------|-----------|
| kc/helpers_test.go | 80 | 4 |
| mcp/helpers_test.go | 478 | 18 |
| app/helpers_test.go | 115 | 11 |
| oauth/helpers_test.go | 172 | 16 |

### kc/helpers_test.go Functions

1. `kiteEnvelope()` — wraps data in Kite API JSON envelope
2. `newMockKiteServer()` — returns httptest.Server for session token/profile endpoints
3. `newKiteClientWithMock()` — creates kiteconnect.Client pointed at mock server
4. `newTestManagerWithDB()` — creates Manager with in-memory SQLite

### Evidence of Duplication

Helper functions `newTestInstrumentsManager()` and `testLogger()` are defined in:
- **kc/manager_test.go** (lines 20, 72) — referenced by kc/helpers_test.go:71-72

This creates implicit coupling and fragmentation — the helpers file depends on external *_test.go definitions.

---

## CLAIM 3: kc/ops/helpers_test.go and kc/alerts/helpers_test.go Do NOT Exist

**STATUS: TRUE**

### Verification

```bash
ls kc/ops/helpers_test.go  # No such file
ls kc/alerts/helpers_test.go # No such file
```

### Mock Type Counts in kc/ops/ and kc/alerts/

| Package | Mock Types |
|---------|-----------|
| kc/ops/ | 2 |
| kc/alerts/ | 5 |

**Pattern:** Mock definitions are embedded in specific *_test.go files (e.g., handler_test.go, briefing_test.go) without a shared helpers module.

---

## CLAIM 4: 51 Mock Struct Definitions Scattered Across 7+ kc/ Test Files

**STATUS: TRUE**

### Total Mock Count
```
grep -rn "^type mock" --include="*_test.go" kc/
```
**Result: 51 mock types**

### Unique Files with Mocks

```
grep -rn "^type mock" --include="*_test.go" kc/ | cut -d: -f1 | sort -u | wc -l
```
**Result: 20 unique files** (exceeds "7+" claim)

### Top 5 Files by Mock Count

| File | Mock Count |
|------|-----------|
| kc/usecases/usecases_edge_test.go | 13 |
| kc/usecases/mf_usecases_test.go | 5 |
| kc/usecases/usecases_test.go | 4 |
| kc/stores_test.go | 4 |
| kc/telegram/commands_test.go | 3 |

**Fragment evidence:** 51 mocks across 20 files with no centralized test helper organization, indicating high test maintenance burden.

---

## Summary Table

| Claim | Status | Key Finding |
|-------|--------|-------------|
| 1. 8 CQRS Bypasses | PARTIAL | 4 confirmed (not 8); middleware + post-exec enrichment |
| 2. Incomplete helpers | TRUE | 80 vs 478 lines; kc relies on manager_test.go |
| 3. No ops/alerts helpers | TRUE | Both missing; mocks embedded in *_test.go |
| 4. 51 mocks × 7+ files | TRUE | 51 mocks × 20 files (exceeds "7+") |

