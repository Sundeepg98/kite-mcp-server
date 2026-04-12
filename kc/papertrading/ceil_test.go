package papertrading

// ceil_test.go — coverage ceiling documentation for kc/papertrading.
// Current: 98.1%. Ceiling: 98.1%.
//
// ===========================================================================
// engine.go:111 — PlaceOrder (98.4%)
// ===========================================================================
//
// Line 114: `e.store.GetAccount(email) err` — DB query error.
//   GetAccount runs a simple SELECT on paper_accounts. With an in-memory
//   SQLite DB, this query always succeeds if InitTables has been called.
//   Unreachable without closing the DB.
//
// ===========================================================================
// engine.go:424 — ModifyOrder (94.1%)
// ===========================================================================
//
// Lines 461-467: `e.store.GetAccount err` + `e.store.UpdateOrderStatus err`
//   in the marketable-LIMIT fill path. Requires the DB to fail between
//   GetOrder (which succeeds) and GetAccount/UpdateOrderStatus calls.
//   With in-memory SQLite, these sequential operations always succeed.
//   Unreachable.
//
// Line 479-480: `e.store.db.ExecInsert UPDATE err` — DB write failure.
//   Same pattern: requires DB corruption mid-function. Unreachable.
//
// ===========================================================================
// engine.go:487 — CancelOrder (90.9%)
// ===========================================================================
//
// Line 498-499: `e.store.UpdateOrderStatus err` — DB write failure after
//   successful GetOrder. Same unreachable pattern.
//
// ===========================================================================
// middleware.go:123 — handleClosePosition (100%) — COVERED by push100_test.go
// ===========================================================================
//
// Lines 141-142: `qty == 0` → "Position already flat".
//   Now covered: TestHandleClosePosition_ZeroQuantity inserts a 0-qty position
//   directly via store.UpsertPosition and verifies the "already flat" response.
//
// ===========================================================================
// middleware.go:158 — handleCloseAllPositions (100%) — COVERED
// ===========================================================================
//
// Lines 171-173: `qty < 0` path in the loop.
//   Covered by TestHandleCloseAllPositions_ShortPositions (coverage_push_test.go).
// Lines 175: `qty == 0` continue path.
//   Covered by TestHandleCloseAllPositions_SkipsZeroQuantity (push100_test.go).
// Lines 186-191: `PlaceOrder err` during close-all.
//   Covered by TestHandleCloseAllPositions_DisabledAccount (push100_test.go).
//   Disables account after creating position → PlaceOrder fails with "not enabled".
//
// ===========================================================================
// monitor.go:147 — fill (83.3%)
// ===========================================================================
//
// Lines 148-151: `m.engine.store.GetAccount err || acct == nil` — DB failure
//   or missing account. GetAccount only fails with DB errors. The monitor
//   only processes orders for enabled accounts. Unreachable.
//
// Lines 158-165: `cost > acct.CashBalance` insufficient-cash rejection path.
//   Now covered: TestMonitorFill_InsufficientCash (push100_test.go) drains
//   cash between order placement and monitor tick, triggering rejection.
//   Inner error path (lines 159-161 UpdateOrderStatus err) remains unreachable.
//
// Lines 169-171: `UpdateOrderStatus err` — DB write failure. Unreachable.
// Lines 180-182: `UpdateCashBalance err` — DB write failure. Unreachable.
// Lines 188-190: `updatePosition err` — DB write failure. Unreachable.
// Lines 195-197: `updateHolding err` — DB write failure. Unreachable.
//
// ===========================================================================
// store.go:296 — GetPositions (90.9%)
// ===========================================================================
//
// Lines 308-310: `rows.Scan err` — scan error after successful query.
//   SQLite dynamic typing ensures scan always succeeds. Unreachable.
//
// ===========================================================================
// store.go:336 — GetHoldings (90.9%)
// ===========================================================================
//
// Lines 348-350: `rows.Scan err` — same as GetPositions. Unreachable.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// Uncovered lines fall into:
//   1. DB failure paths in sequential operations (engine, monitor, store)
//      - engine.go:257-259 UpdateCashBalance error (fillOrder)
//      - engine.go:466-468 UpdateOrderStatus error (ModifyOrder fill)
//      - engine.go:479-481 ExecInsert UPDATE error (ModifyOrder)
//      - engine.go:498-500 UpdateOrderStatus error (CancelOrder)
//      - monitor.go:159-161 UpdateOrderStatus error (insufficient-cash reject)
//      - monitor.go:169-172 UpdateOrderStatus error (fill)
//      - monitor.go:180-183 UpdateCashBalance error (fill)
//   2. rows.Scan errors (SQLite dynamic typing)
//      - store.go:309-311 GetPositions scan
//      - store.go:349-351 GetHoldings scan
//
// All 9 uncovered blocks require in-memory SQLite to fail between two
// sequential operations that always succeed. True ceiling.
//
// Ceiling: 98.1% (9 unreachable blocks, ~11 lines).
