//go:build !race

package mcp

// raceEnabled is false when the binary is built without `-race`. Tests
// that indirectly invoke the gokiteconnect v4 WebSocket ticker
// (ServeWithContext at ticker.go:297 writes to websocket.DefaultDialer,
// a package-level global shared across every Ticker instance — an
// external SDK bug) should skip when this flag is true.
//
// See kc/ticker/race_flag_off_test.go for the original rationale; this
// file exists so the same pattern can be applied to mcp-package tests
// that start tickers via the MCP tool layer (start_ticker, auto-ticker
// inside set_alert).
const raceEnabled = false
