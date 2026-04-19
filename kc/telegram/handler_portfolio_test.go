package telegram

// Tests for handler functions that interact with Kite API via a fake HTTP server.
// These cover the handler body code paths that were at low coverage:
// handlePrice, handlePortfolio, handlePositions, handleOrders,
// handlePnL, handlePrices, handleMyWatchlist, executeConfirmedOrder.

import (
	"fmt"
	"strings"
	"testing"
)

// fakeKiteAPI type is defined in handler_test.go (shared across split files).


// ===========================================================================
// handlePortfolio — full body coverage
// ===========================================================================
func TestHandlePortfolio_SuccessfulHoldings(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{
		{
			"tradingsymbol":         "INFY",
			"quantity":              10,
			"average_price":         1400.0,
			"last_price":            1500.0,
			"day_change":            150.0,
			"day_change_percentage": 1.5,
		},
		{
			"tradingsymbol":         "TCS",
			"quantity":              5,
			"average_price":         3200.0,
			"last_price":            3300.0,
			"day_change":            -50.0,
			"day_change_percentage": -0.3,
		},
	}

	result := h.handlePortfolio(42, email)
	if !strings.Contains(result, "Portfolio") {
		t.Errorf("expected 'Portfolio' header, got: %s", result)
	}
	if !strings.Contains(result, "2 stocks") {
		t.Errorf("expected '2 stocks', got: %s", result)
	}
	if !strings.Contains(result, "Invested") {
		t.Errorf("expected 'Invested' summary, got: %s", result)
	}
	if !strings.Contains(result, "Top movers") {
		t.Errorf("expected 'Top movers', got: %s", result)
	}
}


func TestHandlePortfolio_EmptyHoldings(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{}

	result := h.handlePortfolio(42, email)
	if !strings.Contains(result, "No holdings") {
		t.Errorf("expected 'No holdings', got: %s", result)
	}
}


func TestHandlePortfolio_APIFailure(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	result := h.handlePortfolio(42, email)
	if !strings.Contains(result, "Failed") {
		t.Errorf("expected failure message, got: %s", result)
	}
}


func TestHandlePortfolio_AllZeroDayChange(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{
		{
			"tradingsymbol":         "INFY",
			"quantity":              10,
			"average_price":         1400.0,
			"last_price":            1400.0,
			"day_change":            0.0,
			"day_change_percentage": 0.0,
		},
	}

	result := h.handlePortfolio(42, email)
	if !strings.Contains(result, "Portfolio") {
		t.Errorf("expected 'Portfolio', got: %s", result)
	}
	// "Top movers" section should exist but no stocks listed (all 0%).
}


// ===========================================================================
// handlePositions — full body coverage
// ===========================================================================
func TestHandlePositions_LongAndShort(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{
			{
				"tradingsymbol": "RELIANCE",
				"quantity":      10,
				"pnl":           500.0,
				"product":       "CNC",
			},
			{
				"tradingsymbol": "SBIN",
				"quantity":      -5,
				"pnl":           -200.0,
				"product":       "MIS",
			},
			{
				"tradingsymbol": "ZERO",
				"quantity":      0,
				"pnl":           0.0,
				"product":       "CNC",
			},
		},
		"day": []map[string]interface{}{},
	}

	result := h.handlePositions(42, email)
	if !strings.Contains(result, "Open Positions") {
		t.Errorf("expected 'Open Positions', got: %s", result)
	}
	if !strings.Contains(result, "RELIANCE") {
		t.Errorf("expected 'RELIANCE', got: %s", result)
	}
	if !strings.Contains(result, "LONG") {
		t.Errorf("expected 'LONG', got: %s", result)
	}
	if !strings.Contains(result, "SHORT") {
		t.Errorf("expected 'SHORT', got: %s", result)
	}
	if !strings.Contains(result, "(2)") {
		t.Errorf("expected 2 open positions, got: %s", result)
	}
	if !strings.Contains(result, "Total:") {
		t.Errorf("expected 'Total:', got: %s", result)
	}
}


func TestHandlePositions_AllClosed(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{
			{
				"tradingsymbol": "INFY",
				"quantity":      0,
				"pnl":           0.0,
				"product":       "CNC",
			},
		},
		"day": []map[string]interface{}{},
	}

	result := h.handlePositions(42, email)
	if !strings.Contains(result, "No open positions") {
		t.Errorf("expected 'No open positions', got: %s", result)
	}
}


func TestHandlePositions_APIFailure(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	result := h.handlePositions(42, email)
	if !strings.Contains(result, "Failed") {
		t.Errorf("expected failure message, got: %s", result)
	}
}


// ===========================================================================
// handleOrders — full body coverage
// ===========================================================================
func TestHandleOrders_MultipleStatuses(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders"] = []map[string]interface{}{
		{
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"quantity":         10,
			"product":          "CNC",
			"average_price":    1500.0,
			"status":           "COMPLETE",
		},
		{
			"tradingsymbol":    "TCS",
			"transaction_type": "SELL",
			"quantity":         5,
			"product":          "MIS",
			"average_price":    3300.0,
			"status":           "REJECTED",
		},
	}

	result := h.handleOrders(42, email)
	if !strings.Contains(result, "Orders") {
		t.Errorf("expected 'Orders' header, got: %s", result)
	}
	if !strings.Contains(result, "BUY") {
		t.Errorf("expected 'BUY', got: %s", result)
	}
	if !strings.Contains(result, "\u2705") {
		t.Errorf("expected checkmark for COMPLETE, got: %s", result)
	}
	if !strings.Contains(result, "\u274C") {
		t.Errorf("expected cross for REJECTED, got: %s", result)
	}
}


func TestHandleOrders_EmptyList(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders"] = []map[string]interface{}{}

	result := h.handleOrders(42, email)
	if !strings.Contains(result, "No orders") {
		t.Errorf("expected 'No orders', got: %s", result)
	}
}


func TestHandleOrders_PaginationOver10(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	orders := make([]map[string]interface{}, 15)
	for i := 0; i < 15; i++ {
		orders[i] = map[string]interface{}{
			"tradingsymbol":    fmt.Sprintf("SYM%d", i),
			"transaction_type": "BUY",
			"quantity":         1,
			"product":          "CNC",
			"average_price":    100.0,
			"status":           "COMPLETE",
		}
	}
	fakeAPI.responses["/orders"] = orders

	result := h.handleOrders(42, email)
	if !strings.Contains(result, "showing last 10") {
		t.Errorf("expected 'showing last 10', got: %s", result)
	}
}


func TestHandleOrders_CancelledAndPendingStatus(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders"] = []map[string]interface{}{
		{
			"tradingsymbol":    "SYM1",
			"transaction_type": "BUY",
			"quantity":         1,
			"product":          "CNC",
			"average_price":    0,
			"status":           "CANCELLED",
		},
		{
			"tradingsymbol":    "SYM2",
			"transaction_type": "SELL",
			"quantity":         2,
			"product":          "MIS",
			"average_price":    0,
			"status":           "OPEN",
		},
	}

	result := h.handleOrders(42, email)
	if !strings.Contains(result, "\U0001F6AB") {
		t.Errorf("expected no-entry emoji for CANCELLED, got: %s", result)
	}
	if !strings.Contains(result, "\u23F3") {
		t.Errorf("expected hourglass emoji for OPEN/pending, got: %s", result)
	}
}


// ===========================================================================
// handlePnL — full body coverage
// ===========================================================================
func TestHandlePnL_HoldingsAndPositions(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{
		{"tradingsymbol": "INFY", "quantity": 10, "average_price": 1400.0, "last_price": 1500.0, "day_change": 300.0},
		{"tradingsymbol": "TCS", "quantity": 5, "average_price": 3200.0, "last_price": 3300.0, "day_change": -50.0},
	}
	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{},
		"day": []map[string]interface{}{
			{"tradingsymbol": "SBIN", "quantity": 20, "pnl": 200.0, "product": "MIS"},
		},
	}

	result := h.handlePnL(42, email)
	if !strings.Contains(result, "P&amp;L") {
		t.Errorf("expected P&L header, got: %s", result)
	}
	if !strings.Contains(result, "Holdings") {
		t.Errorf("expected 'Holdings', got: %s", result)
	}
	if !strings.Contains(result, "Positions") {
		t.Errorf("expected 'Positions', got: %s", result)
	}
	if !strings.Contains(result, "Net:") {
		t.Errorf("expected 'Net:', got: %s", result)
	}
}


func TestHandlePnL_HoldingsUnavailable(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// Only positions configured.
	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{},
		"day": []map[string]interface{}{},
	}

	result := h.handlePnL(42, email)
	if !strings.Contains(result, "unavailable") {
		t.Errorf("expected 'unavailable' for holdings, got: %s", result)
	}
}


func TestHandlePnL_PositionsUnavailable(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{}
	// No positions configured.

	result := h.handlePnL(42, email)
	if !strings.Contains(result, "unavailable") {
		t.Errorf("expected 'unavailable' for positions, got: %s", result)
	}
}


func TestHandlePnL_BothUnavailable(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	result := h.handlePnL(42, email)
	if !strings.Contains(result, "P&amp;L") {
		t.Errorf("expected P&L header even with errors, got: %s", result)
	}
}
