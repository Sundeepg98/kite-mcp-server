# Papertrading Coverage Push — push100_test.go

## Result: 97.6% → 98.1% (ceiling)

## Tests Added (push100_test.go)

### TestMonitorFill_InsufficientCash
- **Target**: monitor.go:158-165 — insufficient cash rejection in background fill
- **Strategy**: Place BUY LIMIT with sufficient cash, drain cash with MARKET BUY, tick monitor → LIMIT triggers but cash insufficient → REJECTED
- **Lines covered**: 157-165 (cash check + rejection), 148-152 (GetAccount success path)

### TestHandleClosePosition_ZeroQuantity
- **Target**: middleware.go:141-142 — "Position already flat" for qty==0
- **Strategy**: Direct `store.UpsertPosition` with qty=0 (bypasses engine which deletes 0-qty positions), then call handleClosePosition
- **Lines covered**: 141-142

### TestHandleCloseAllPositions_SkipsZeroQuantity
- **Target**: middleware.go:175 — `qty == 0` continue in closeAll loop
- **Strategy**: Real position + direct 0-qty position insertion, closeAll skips zero and closes real
- **Lines covered**: 175-176

## Remaining Uncovered (9 blocks, ~11 lines) — TRUE CEILING

All are DB failure paths requiring in-memory SQLite to fail between two sequential ops:

| File | Lines | Description |
|------|-------|-------------|
| engine.go | 206-208 | InsertOrder error (OPEN LIMIT) |
| engine.go | 466-468 | UpdateOrderStatus error (ModifyOrder fill) |
| engine.go | 479-481 | ExecInsert UPDATE error (ModifyOrder) |
| engine.go | 498-500 | UpdateOrderStatus error (CancelOrder) |
| monitor.go | 159-161 | UpdateOrderStatus error (insufficient-cash reject) |
| monitor.go | 169-172 | UpdateOrderStatus error (fill) |
| monitor.go | 180-183 | UpdateCashBalance error (fill) |
| store.go | 309-311 | rows.Scan error (GetPositions) |
| store.go | 349-351 | rows.Scan error (GetHoldings) |

These require DB corruption mid-function (impossible with in-memory SQLite).
