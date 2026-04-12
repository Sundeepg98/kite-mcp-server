package ops

// ceil_test.go — coverage ceiling documentation for kc/ops.
// Current: 89.4%. Ceiling: ~89%.
//
// The ops package implements the dashboard HTTP handlers for portfolio,
// activity timeline, market indices, orders, alerts, paper trading, sector
// exposure, and tax analysis. Most uncovered lines involve:
//   1. Kite API calls that require live credentials + access tokens
//   2. SSE streaming with long-lived connections
//   3. Template rendering edge cases
//
// ===========================================================================
// dashboard.go — activityStreamSSE (73.5%)
// ===========================================================================
//
// Lines 568-610: SSE event loop with keepalive ticker + listener channel.
//   The SSE handler creates a long-lived connection and blocks on a select
//   between the client disconnect (r.Context().Done()), keepalive ticker
//   (15s), and audit trail listener channel. Testing requires:
//   (a) A real SSE client that maintains the connection, or
//   (b) Mocking the Flusher + waiting for the ticker.
//   The event serialization and filtering logic is testable, but the
//   long-lived connection lifecycle is not easily unit-tested.
//
// ===========================================================================
// dashboard.go — marketIndices (72.4%)
// ===========================================================================
//
// Lines 708-735: Kite API call to GetOHLC for NIFTY 50, BANK NIFTY, SENSEX.
//   Requires valid credential + token entries in the store. The Kite API
//   call (client.GetOHLC) makes a real HTTP request. Cannot be tested
//   without mocking the Kite HTTP client or using live credentials.
//   The OHLC → change percentage calculation IS reachable but is behind
//   the API call.
//
// ===========================================================================
// dashboard.go — portfolio (75.9%)
// ===========================================================================
//
// Lines 770-840: Kite API calls to GetHoldings + GetPositions.
//   Same dependency on live Kite credentials. The enrichment logic
//   (computing unrealized P&L, sector exposure) is behind the API calls.
//
// ===========================================================================
// dashboard.go — ordersAPI (47.1%)
// ===========================================================================
//
// Lines 1014-1080+: Kite API enrichment of audit trail order entries.
//   After listing orders from audit store (which IS tested), the handler
//   fetches OHLC data from Kite to compute current P&L. This requires
//   live credentials. The bulk of uncovered code is the enrichment logic:
//   parsing order parameters, computing P&L from OHLC data, and building
//   the response JSON.
//
// ===========================================================================
// dashboard.go — paper* handlers (82.4% each)
// ===========================================================================
//
// paperStatus, paperHoldings, paperPositions, paperOrders, paperReset:
//   Each handler requires paper trading to be enabled for the user AND
//   valid credentials. The uncovered lines are the success paths that call
//   the paper trading engine. Error paths (not enabled, auth failures) are
//   tested.
//
// ===========================================================================
// dashboard.go — sectorExposureAPI (81.5%)
// ===========================================================================
//
// Lines 1779-1850+: Kite API call to GetHoldings + sector mapping.
//   Requires live Kite credentials for holdings data. The sector mapping
//   logic itself is in mcp/sector_tool.go (fully tested).
//
// ===========================================================================
// dashboard.go — taxAnalysisAPI (81.5%)
// ===========================================================================
//
// Lines 1944-2020+: Kite API call to GetTrades + tax computation.
//   Same Kite credentials dependency.
//
// ===========================================================================
// dashboard.go — alertsEnrichedAPI (86.1%)
// ===========================================================================
//
// Lines 1264-1350+: Alert list + LTP enrichment from Kite API.
//   Success path requires Kite credentials for LTP data.
//
// ===========================================================================
// dashboard.go — writeJSONError (75.0%)
// ===========================================================================
//
// Line 386-390: JSON encoding error in error response.
//   json.NewEncoder().Encode on a simple map[string]any always succeeds
//   with httptest.NewRecorder. Unreachable.
//
// ===========================================================================
// dashboard.go — RegisterRoutes (92.7%)
// ===========================================================================
//
// Lines 310-315: SSO cookie check + billing page routes.
//   Requires specific SSO configuration state.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// The dominant pattern is Kite API enrichment paths. The dashboard handlers
// fetch data from audit/alert stores (tested), then call the Kite API to
// enrich with live market data (not testable without mocking the Kite HTTP
// client). The SSE handler also requires long-lived connections.
//
// Ceiling: ~89% (~60 unreachable lines, mostly behind Kite API calls).
