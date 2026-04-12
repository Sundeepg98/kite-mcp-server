package audit

// ceil_test.go — coverage ceiling documentation for kc/audit.
// Current: 97.2%. Ceiling: 97.2%.
//
// All uncovered lines are documented in store_push100_test.go (lines 214-252)
// with full analysis. This file provides the consolidated summary.
//
// ===========================================================================
// middleware.go:16 — Middleware (97.5%)
// ===========================================================================
//
// Line 33-35: `server.ClientSessionFromContext(ctx) sess != nil` branch.
//   Requires a full MCP server transport context with an active client session.
//   Unit tests use plain context.Background() which has no session attached.
//   The session extraction is a simple SessionID() call — the middleware logic
//   around it is fully tested. Unreachable in unit tests.
//
// ===========================================================================
// store.go — rows.Err() paths (8 instances)
// ===========================================================================
//
// Lines 356-358 (List), 443-445 (ListOrders), 498-500 (GetOrderAttribution),
// 668-670 (GetToolCounts), 712-714 (GetToolMetrics), 796-798 (GetTopErrorUsers),
// 945-947 (VerifyChain), and the implicit rows.Err in List.
//
// The SQLite driver (modernc.org/sqlite) does not produce mid-iteration errors.
// rows.Err() always returns nil after rows.Next() returns false. These are
// defensive guards mandated by the database/sql API contract. Unreachable.
//
// ===========================================================================
// store.go — rows.Scan error paths (4 instances)
// ===========================================================================
//
// Lines 663-665 (GetToolCounts), 707-709 (GetToolMetrics),
// 784-786 (GetTopErrorUsers), 878-880 (VerifyChain).
//
// These scan aggregate query results (COUNT(*), AVG, MAX, SUM). SQLite's
// dynamic typing ensures these always return scannable values. The column
// types match the destination Go types. Unreachable.
//
// ===========================================================================
// store.go — DeleteOlderThan (87.0%)
// ===========================================================================
//
// Lines 519-520, 523-525: ExecResult error on DELETE + RowsAffected error.
//   The hash-lookup QueryRow on line 512 succeeds before the DELETE. For the
//   DELETE to fail while the QueryRow succeeded, the DB must become corrupt
//   between the two calls. RowsAffected on SQLite always succeeds.
//   Unreachable.
//
// ===========================================================================
// store.go — GetStats (96.6%) / GetGlobalStats (93.8%)
// ===========================================================================
//
// Lines 612-614 (GetStats), 737-739 (GetGlobalStats): top-tool query error
//   (non-ErrNoRows). Requires the DB to become corrupt between the aggregate
//   query and the GROUP BY query within the same function call. Unreachable.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// All uncovered lines are:
//   1. MCP transport context (middleware.go) — requires full server transport
//   2. rows.Err() after iteration — SQLite driver guarantee
//   3. rows.Scan on aggregate queries — SQLite dynamic typing
//   4. Sequential DB operations where first succeeds but second fails
//
// Ceiling: 97.2% (~20 unreachable lines).
// Detailed per-line documentation: store_push100_test.go lines 214-252.
