package telegram

// Tests for handler functions that interact with Kite API via a fake HTTP server.
// These cover the handler body code paths that were at low coverage:
// handlePrice, handlePortfolio, handlePositions, handleOrders,
// handlePnL, handlePrices, handleMyWatchlist, executeConfirmedOrder.

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"path/filepath"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// ---------------------------------------------------------------------------
// fakeKiteAPI — httptest.Server mimicking Kite Connect API responses.
// ---------------------------------------------------------------------------

type fakeKiteAPI struct {
	server    *httptest.Server
	responses map[string]interface{} // path → data payload
}

func newFakeKiteAPI() *fakeKiteAPI {
	f := &fakeKiteAPI{
		responses: make(map[string]interface{}),
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		data, ok := f.responses[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"status":     "error",
				"message":    "not found: " + path,
				"error_type": "GeneralException",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": data,
		})
	}))
	return f
}

func (f *fakeKiteAPI) close() {
	f.server.Close()
}

// newTestBotWithFakeAPI creates a BotHandler wired to a fake Kite API server.
func newTestBotWithFakeAPI(t *testing.T, email string) (*BotHandler, *mockHTTPClient, *fakeKiteAPI) {
	t.Helper()
	fakeAPI := newFakeKiteAPI()
	mgr := newMockKiteManager()
	mgr.apiKeys[email] = "test-api-key"
	mgr.accessTokens[email] = "test-access-token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	return h, mock, fakeAPI
}

// ===========================================================================
// handlePrice — successful API call paths
// ===========================================================================

func TestHandlePrice_SuccessfulQuote(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.50,
			"volume":     12345678,
			"ohlc": map[string]interface{}{
				"open":  1490.0,
				"high":  1510.0,
				"low":   1485.0,
				"close": 1480.0,
			},
		},
	}

	result := h.handlePrice(42, email, "INFY")
	if !strings.Contains(result, "1500.50") {
		t.Errorf("expected price 1500.50 in result, got: %s", result)
	}
	if !strings.Contains(result, "NSE:INFY") {
		t.Errorf("expected symbol NSE:INFY in result, got: %s", result)
	}
	if !strings.Contains(result, "1510.00") {
		t.Errorf("expected high 1510.00, got: %s", result)
	}
	if !strings.Contains(result, "1485.00") {
		t.Errorf("expected low 1485.00, got: %s", result)
	}
}

func TestHandlePrice_APIReturnsError(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// No /quote response configured → 404 from fake server.
	result := h.handlePrice(42, email, "INFY")
	if !strings.Contains(result, "Failed") && !strings.Contains(result, "No data") {
		t.Errorf("expected error or no-data message, got: %s", result)
	}
}

func TestHandlePrice_SymbolNotInQuote(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{}
	result := h.handlePrice(42, email, "NONEXISTENT")
	if !strings.Contains(result, "No data") {
		t.Errorf("expected 'No data', got: %s", result)
	}
}

func TestHandlePrice_WithExchangePrefix(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"BSE:RELIANCE": map[string]interface{}{
			"last_price": 2500.00,
			"volume":     5000000,
			"ohlc": map[string]interface{}{
				"open": 2480.0, "high": 2520.0, "low": 2475.0, "close": 2490.0,
			},
		},
	}

	result := h.handlePrice(42, email, "BSE:RELIANCE")
	if !strings.Contains(result, "2500.00") {
		t.Errorf("expected price 2500.00, got: %s", result)
	}
}

func TestHandlePrice_ZeroClosePrice(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:NEWIPO": map[string]interface{}{
			"last_price": 100.0,
			"volume":     1000,
			"ohlc": map[string]interface{}{
				"open": 100.0, "high": 105.0, "low": 95.0, "close": 0.0,
			},
		},
	}

	result := h.handlePrice(42, email, "NEWIPO")
	if !strings.Contains(result, "100.00") {
		t.Errorf("expected price 100.00, got: %s", result)
	}
	// Zero close → 0% change.
	if !strings.Contains(result, "+0.00%") {
		t.Errorf("expected +0.00%% for zero close, got: %s", result)
	}
}

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

// ===========================================================================
// handlePrices — successful multi-symbol paths
// ===========================================================================

func TestHandlePrices_MultipleSymbols(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
			"ohlc": map[string]interface{}{
				"open": 1490.0, "high": 1510.0, "low": 1485.0, "close": 1480.0,
			},
		},
		"NSE:TCS": map[string]interface{}{
			"last_price": 3300.0,
			"ohlc": map[string]interface{}{
				"open": 3280.0, "high": 3320.0, "low": 3270.0, "close": 3290.0,
			},
		},
	}

	result := h.handlePrices(42, email, "INFY,TCS")
	if !strings.Contains(result, "Prices") {
		t.Errorf("expected 'Prices' header, got: %s", result)
	}
	if !strings.Contains(result, "INFY") {
		t.Errorf("expected 'INFY', got: %s", result)
	}
	if !strings.Contains(result, "TCS") {
		t.Errorf("expected 'TCS', got: %s", result)
	}
	if !strings.Contains(result, "1500.00") {
		t.Errorf("expected 1500.00, got: %s", result)
	}
}

func TestHandlePrices_PartialNotFound(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
			"ohlc": map[string]interface{}{
				"open": 0.0, "high": 0.0, "low": 0.0, "close": 0.0,
			},
		},
	}

	result := h.handlePrices(42, email, "INFY,NOSUCHSYM")
	if !strings.Contains(result, "not found") {
		t.Errorf("expected 'not found' for missing symbol, got: %s", result)
	}
}

func TestHandlePrices_ZeroClosePrice(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:NEWIPO": map[string]interface{}{
			"last_price": 100.0,
			"ohlc": map[string]interface{}{
				"open": 100.0, "high": 105.0, "low": 95.0, "close": 0.0,
			},
		},
	}

	result := h.handlePrices(42, email, "NEWIPO")
	if !strings.Contains(result, "+0.00%") {
		t.Errorf("expected +0.00%% for zero close, got: %s", result)
	}
}

func TestHandlePrices_APIFailure(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// No response configured → error.
	result := h.handlePrices(42, email, "INFY")
	if !strings.Contains(result, "Failed") {
		t.Errorf("expected 'Failed', got: %s", result)
	}
}

func TestHandlePrices_WhitespaceSymbols(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
			"ohlc": map[string]interface{}{
				"open": 0.0, "high": 0.0, "low": 0.0, "close": 1480.0,
			},
		},
	}

	result := h.handlePrices(42, email, "  INFY  ,  ")
	if !strings.Contains(result, "INFY") {
		t.Errorf("expected 'INFY' with whitespace trimmed, got: %s", result)
	}
}

// ===========================================================================
// handleMyWatchlist — various paths
// ===========================================================================

func TestHandleMyWatchlist_EmptyWatchlistList(t *testing.T) {
	email := "user@test.com"
	store := watchlist.NewStore()
	mgr := newMockKiteManager()
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true
	mgr.watchlistStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleMyWatchlist(42, email)
	if !strings.Contains(result, "No watchlists") {
		t.Errorf("expected 'No watchlists', got: %s", result)
	}
}

func TestHandleMyWatchlist_WithItemsAndLTP(t *testing.T) {
	email := "user@test.com"
	store := watchlist.NewStore()
	wlID, err := store.CreateWatchlist(email, "My Stocks")
	if err != nil {
		t.Fatalf("failed to create watchlist: %v", err)
	}
	_ = store.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		TargetEntry:   1400.0,
		TargetExit:    1600.0,
	})
	_ = store.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "TCS",
	})

	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/quote/ltp"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
		},
		"NSE:TCS": map[string]interface{}{
			"last_price": 3300.0,
		},
	}

	mgr := newMockKiteManager()
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true
	mgr.watchlistStore = store

	h, _ := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	result := h.handleMyWatchlist(42, email)
	if !strings.Contains(result, "My Watchlists") {
		t.Errorf("expected 'My Watchlists', got: %s", result)
	}
	if !strings.Contains(result, "My Stocks") {
		t.Errorf("expected 'My Stocks', got: %s", result)
	}
	if !strings.Contains(result, "INFY") {
		t.Errorf("expected 'INFY', got: %s", result)
	}
}

func TestHandleMyWatchlist_NoKiteClient_ShowsItems(t *testing.T) {
	email := "user@test.com"
	store := watchlist.NewStore()
	wlID, err := store.CreateWatchlist(email, "Test WL")
	if err != nil {
		t.Fatalf("failed to create watchlist: %v", err)
	}
	_ = store.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})

	mgr := newMockKiteManager()
	mgr.watchlistStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleMyWatchlist(42, email)
	if !strings.Contains(result, "INFY") {
		t.Errorf("expected 'INFY' in result, got: %s", result)
	}
}

func TestHandleMyWatchlist_EmptyWatchlistItems(t *testing.T) {
	email := "user@test.com"
	store := watchlist.NewStore()
	_, err := store.CreateWatchlist(email, "Empty WL")
	if err != nil {
		t.Fatalf("failed to create watchlist: %v", err)
	}

	mgr := newMockKiteManager()
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true
	mgr.watchlistStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleMyWatchlist(42, email)
	if !strings.Contains(result, "(empty)") {
		t.Errorf("expected '(empty)', got: %s", result)
	}
}

// ===========================================================================
// handleStatus — covered via existing test, but adding expired/valid paths
// ===========================================================================

func TestHandleStatus_ValidCredentials(t *testing.T) {
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "test-key-ABCD"
	mgr.accessTokens["user@test.com"] = "test-token"
	mgr.tokenValid["user@test.com"] = true

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Status") {
		t.Errorf("expected 'Status', got: %s", result)
	}
	if !strings.Contains(result, "ABCD") {
		t.Errorf("expected last 4 of API key, got: %s", result)
	}
	if !strings.Contains(result, "Valid") {
		t.Errorf("expected 'Valid', got: %s", result)
	}
}

func TestHandleStatus_ExpiredCredentials(t *testing.T) {
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "some-key"
	mgr.accessTokens["user@test.com"] = "old-token"
	mgr.tokenValid["user@test.com"] = false

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Expired") {
		t.Errorf("expected 'Expired', got: %s", result)
	}
}

func TestHandleStatus_MissingCredentials(t *testing.T) {
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "nobody@test.com")
	if !strings.Contains(result, "Not configured") {
		t.Errorf("expected 'Not configured', got: %s", result)
	}
	if !strings.Contains(result, "Not found") {
		t.Errorf("expected 'Not found', got: %s", result)
	}
}

// ===========================================================================
// executeConfirmedOrder paths
// ===========================================================================

func TestExecuteConfirmedOrder_NoPendingOrder(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-1",
		Message: &tgbotapi.Message{
			MessageID: 100,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	// No pending order → should handle gracefully.
	h.executeConfirmedOrder(42, email, cq)
}

func TestExecuteConfirmedOrder_EmailMismatch(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	h.setPendingOrder(42, &pendingOrder{
		Email:     "other@test.com",
		CreatedAt: time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-2",
		Message: &tgbotapi.Message{
			MessageID: 101,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
}

func TestExecuteConfirmedOrder_PlacesOrder(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "ORD-12345",
	}

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        10,
		Price:           0,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-3",
		Message: &tgbotapi.Message{
			MessageID: 102,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
}

func TestExecuteConfirmedOrder_NilMessage(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	cq := &tgbotapi.CallbackQuery{
		ID:      "cb-nil-msg",
		Message: nil,
	}

	// No pending order + nil message → should not panic.
	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// ServeHTTP integration tests for handler commands
// ===========================================================================

func TestServeHTTP_PriceCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:SBIN": map[string]interface{}{
			"last_price": 600.0,
			"volume":     50000000,
			"ohlc": map[string]interface{}{
				"open": 595.0, "high": 610.0, "low": 590.0, "close": 598.0,
			},
		},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/price SBIN",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected price message to be sent")
	}
}

func TestServeHTTP_PortfolioCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{
		{
			"tradingsymbol":         "INFY",
			"quantity":              10,
			"average_price":         1400.0,
			"last_price":            1500.0,
			"day_change":            100.0,
			"day_change_percentage": 1.0,
		},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/portfolio",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected portfolio message to be sent")
	}
}

func TestServeHTTP_OrdersCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
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
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/orders",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected orders message to be sent")
	}
}

func TestServeHTTP_PnLCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/holdings"] = []map[string]interface{}{
		{"tradingsymbol": "INFY", "quantity": 10, "average_price": 1400.0, "last_price": 1500.0, "day_change": 100.0},
	}
	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{},
		"day": []map[string]interface{}{},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/pnl",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected PnL message to be sent")
	}
}

func TestServeHTTP_PositionsCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/portfolio/positions"] = map[string]interface{}{
		"net": []map[string]interface{}{
			{"tradingsymbol": "RELIANCE", "quantity": 10, "pnl": 500.0, "product": "CNC"},
		},
		"day": []map[string]interface{}{},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/positions",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected positions message to be sent")
	}
}

func TestServeHTTP_PricesCommandIntegration(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
			"ohlc": map[string]interface{}{
				"open": 0.0, "high": 0.0, "low": 0.0, "close": 1480.0,
			},
		},
		"NSE:TCS": map[string]interface{}{
			"last_price": 3300.0,
			"ohlc": map[string]interface{}{
				"open": 0.0, "high": 0.0, "low": 0.0, "close": 3290.0,
			},
		},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/prices INFY,TCS",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected prices message to be sent")
	}
}

func TestServeHTTP_MywatchlistCommandIntegration(t *testing.T) {
	email := "user@test.com"

	store := watchlist.NewStore()
	wlID, err := store.CreateWatchlist(email, "Favs")
	if err != nil {
		t.Fatalf("failed to create watchlist: %v", err)
	}
	_ = store.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "HDFC",
	})

	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/quote/ltp"] = map[string]interface{}{
		"NSE:HDFC": map[string]interface{}{
			"last_price": 2800.0,
		},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true
	mgr.watchlistStore = store

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/mywatchlist",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected mywatchlist message to be sent")
	}
}

// ===========================================================================
// sendHTML / sendHTMLWithKeyboard / answerCallback / editMessage error paths
// ===========================================================================

func TestSendHTML_BotError(t *testing.T) {
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	// Make the mock return an API error so bot.Send() fails.
	mock.mu.Lock()
	mock.responseObj = tgbotapi.APIResponse{
		Ok:          false,
		ErrorCode:   400,
		Description: "Bad Request: chat not found",
	}
	mock.mu.Unlock()

	// Should not panic — the error is just logged.
	h.sendHTML(42, "test message")
}

func TestSendHTMLWithKeyboard_BotError(t *testing.T) {
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	mock.mu.Lock()
	mock.responseObj = tgbotapi.APIResponse{
		Ok:          false,
		ErrorCode:   403,
		Description: "Forbidden: bot was blocked by the user",
	}
	mock.mu.Unlock()

	kb := confirmKeyboard()
	h.sendHTMLWithKeyboard(42, "test", kb)
}

func TestAnswerCallback_BotError(t *testing.T) {
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	mock.mu.Lock()
	mock.responseObj = tgbotapi.APIResponse{
		Ok:          false,
		ErrorCode:   400,
		Description: "Bad Request",
	}
	mock.mu.Unlock()

	h.answerCallback("cb-err", "error test")
}

func TestEditMessage_BotError(t *testing.T) {
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	mock.mu.Lock()
	mock.responseObj = tgbotapi.APIResponse{
		Ok:          false,
		ErrorCode:   400,
		Description: "Bad Request",
	}
	mock.mu.Unlock()

	h.editMessage(42, 100, "new text")
}

// ===========================================================================
// Helper: create an instruments.Manager with test data
// ===========================================================================

func newTestInstrumentsManager(t *testing.T) *instruments.Manager {
	t.Helper()
	testData := map[uint32]*instruments.Instrument{
		256265: {
			ID:              "NSE:RELIANCE",
			InstrumentToken: 256265,
			Tradingsymbol:   "RELIANCE",
			Exchange:        "NSE",
			Name:            "Reliance Industries",
		},
		408065: {
			ID:              "NSE:INFY",
			InstrumentToken: 408065,
			Tradingsymbol:   "INFY",
			Exchange:        "NSE",
			Name:            "Infosys",
		},
		779521: {
			ID:              "NSE:NIFTY 50",
			InstrumentToken: 779521,
			Tradingsymbol:   "NIFTY 50",
			Exchange:        "NSE",
			Name:            "Nifty 50",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := instruments.New(instruments.Config{
		TestData: testData,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("instruments.New failed: %v", err)
	}
	return mgr
}

// ===========================================================================
// executeConfirmedOrder — riskguard blocking
// ===========================================================================

func TestExecuteConfirmedOrder_RiskguardBlocks(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// Set up riskguard with a global freeze.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	guard := riskguard.NewGuard(logger)
	guard.FreezeGlobal("admin", "circuit breaker")
	mgr := h.manager.(*mockKiteManager)
	mgr.guard = guard

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		Price:           0,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-rg",
		Message: &tgbotapi.Message{
			MessageID: 200,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
	// The order should be blocked; no error/panic expected.
}

// ===========================================================================
// executeConfirmedOrder — riskguard blocks + nil message
// ===========================================================================

func TestExecuteConfirmedOrder_RiskguardBlocksNilMessage(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	guard := riskguard.NewGuard(logger)
	guard.FreezeGlobal("admin", "test freeze")
	mgr := h.manager.(*mockKiteManager)
	mgr.guard = guard

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        5,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID:      "cb-rg-nil",
		Message: nil,
	}

	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// executeConfirmedOrder — paper trading success
// ===========================================================================

func TestExecuteConfirmedOrder_PaperTradingSuccess(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { paperDB.Close() })
	ptStore := papertrading.NewStore(paperDB, logger)
	if err := ptStore.InitTables(); err != nil {
		t.Fatalf("InitTables failed: %v", err)
	}
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000)

	mgr := h.manager.(*mockKiteManager)
	mgr.paperEngine = pe

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        1,
		Price:           2500,
		OrderType:       "LIMIT",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-paper",
		Message: &tgbotapi.Message{
			MessageID: 300,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// executeConfirmedOrder — real order failure (Kite API error)
// ===========================================================================

func TestExecuteConfirmedOrder_RealOrderAPIFailure(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// No /orders/regular configured → Kite API returns error.
	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		Price:           0,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-fail",
		Message: &tgbotapi.Message{
			MessageID: 400,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// executeConfirmedOrder — real order success with riskguard recording
// ===========================================================================

func TestExecuteConfirmedOrder_RealOrderWithRiskguard(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	guard := riskguard.NewGuard(logger)
	mgr := h.manager.(*mockKiteManager)
	mgr.guard = guard

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "ORD-RG-123",
	}

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        5,
		Price:           0,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-rg-success",
		Message: &tgbotapi.Message{
			MessageID: 500,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// executeConfirmedOrder — no kite client (expired token)
// ===========================================================================

func TestExecuteConfirmedOrder_NoKiteClient(t *testing.T) {
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	// No API key set → newKiteClient returns nil.

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.setPendingOrder(42, &pendingOrder{
		Email:           "user@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        5,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-noclient",
		Message: &tgbotapi.Message{
			MessageID: 600,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.executeConfirmedOrder(42, "user@test.com", cq)
}

// ===========================================================================
// executeConfirmedOrder — no kite client + nil message
// ===========================================================================

func TestExecuteConfirmedOrder_NoKiteClientNilMessage(t *testing.T) {
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.setPendingOrder(42, &pendingOrder{
		Email:           "user@test.com",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        5,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID:      "cb-noclient-nil",
		Message: nil,
	}

	h.executeConfirmedOrder(42, "user@test.com", cq)
}

// ===========================================================================
// executeConfirmedOrder — real order success + nil message
// ===========================================================================

func TestExecuteConfirmedOrder_SuccessNilMessage(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "ORD-NM-123",
	}

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        3,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID:      "cb-success-nil",
		Message: nil,
	}

	h.executeConfirmedOrder(42, email, cq)
}

// ===========================================================================
// handleSetAlert — full coverage
// ===========================================================================

func TestHandleSetAlert_Success(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE above 2700")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "RELIANCE") {
		t.Errorf("expected 'RELIANCE', got: %s", result)
	}
	if !strings.Contains(result, "above") {
		t.Errorf("expected 'above', got: %s", result)
	}
	if !strings.Contains(result, "2700.00") {
		t.Errorf("expected '2700.00', got: %s", result)
	}
}

func TestHandleSetAlert_InstrumentNotFound(t *testing.T) {
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "NOSUCHSYMBOL above 100")
	if !strings.Contains(result, "not found") {
		t.Errorf("expected 'not found', got: %s", result)
	}
}

func TestHandleSetAlert_BelowDirection(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "INFY below 1300")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "below") {
		t.Errorf("expected 'below', got: %s", result)
	}
}

// ===========================================================================
// handleAlerts — percentage direction display
// ===========================================================================

func TestHandleAlerts_WithPercentageAlerts(t *testing.T) {
	email := "user@test.com"
	store := alerts.NewStore(nil)
	store.Add(email, "RELIANCE", "NSE", 256265, 5.0, alerts.DirectionDropPct)

	mgr := newMockKiteManager()
	mgr.alertStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleAlerts(42, email)
	if !strings.Contains(result, "Active Alerts") {
		t.Errorf("expected 'Active Alerts', got: %s", result)
	}
	if !strings.Contains(result, "drop_pct") {
		t.Errorf("expected 'drop_pct' direction, got: %s", result)
	}
	if !strings.Contains(result, "5.00%") {
		t.Errorf("expected '5.00%%', got: %s", result)
	}
}

func TestHandleAlerts_MixedDirections(t *testing.T) {
	email := "user@test.com"
	store := alerts.NewStore(nil)
	store.Add(email, "RELIANCE", "NSE", 256265, 2700, alerts.DirectionAbove)
	store.Add(email, "INFY", "NSE", 408065, 3.5, alerts.DirectionRisePct)

	mgr := newMockKiteManager()
	mgr.alertStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleAlerts(42, email)
	if !strings.Contains(result, "2700.00") {
		t.Errorf("expected '2700.00', got: %s", result)
	}
	if !strings.Contains(result, "3.50%") {
		t.Errorf("expected '3.50%%', got: %s", result)
	}
}

func TestHandleAlerts_NoAlerts(t *testing.T) {
	email := "user@test.com"
	store := alerts.NewStore(nil)

	mgr := newMockKiteManager()
	mgr.alertStore = store

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleAlerts(42, email)
	if !strings.Contains(result, "No active alerts") {
		t.Errorf("expected 'No active alerts', got: %s", result)
	}
}

// ===========================================================================
// handleQuick — edge cases
// ===========================================================================

func TestHandleQuick_LimitBadPrice2(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "RELIANCE 10 SELL LIMIT -50")
}

func TestHandleQuick_InvalidQuantity2(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "RELIANCE abc BUY MARKET")
}

func TestHandleSell_LimitSuccess2(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleSell(42, email, "INFY 5 1600")
}

func TestHandleBuy_NegativePrice2(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleBuy(42, email, "RELIANCE 10 -500")
}

// ===========================================================================
// ServeHTTP — callback query path
// ===========================================================================

func TestServeHTTP_CallbackQuery(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		CallbackQuery: &tgbotapi.CallbackQuery{
			ID:   "cb-serv",
			Data: "cancel_order",
			Message: &tgbotapi.Message{
				MessageID: 999,
				Chat:      &tgbotapi.Chat{ID: 42},
			},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_CallbackQuery_UnknownAction(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		CallbackQuery: &tgbotapi.CallbackQuery{
			ID:   "cb-unk",
			Data: "unknown_action",
			Message: &tgbotapi.Message{
				MessageID: 998,
				Chat:      &tgbotapi.Chat{ID: 42},
			},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_CallbackQuery_UnregisteredUser(t *testing.T) {
	mgr := newMockKiteManager()
	// No registered users.

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		CallbackQuery: &tgbotapi.CallbackQuery{
			ID:   "cb-unreg",
			Data: "confirm_order",
			Message: &tgbotapi.Message{
				MessageID: 997,
				Chat:      &tgbotapi.Chat{ID: 999},
			},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestServeHTTP_CallbackQuery_NilMessageNilChat(t *testing.T) {
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		CallbackQuery: &tgbotapi.CallbackQuery{
			ID:      "cb-nil",
			Data:    "confirm_order",
			Message: nil,
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ===========================================================================
// ServeHTTP — empty text message
// ===========================================================================

func TestServeHTTP_EmptyTextMessage(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// No message should be sent for empty text.
	if mock.bodyCount() > 0 {
		t.Error("should not send message for empty text")
	}
}

// ===========================================================================
// ServeHTTP — rate limit exceeded
// ===========================================================================

func TestServeHTTP_RateLimitExceeded(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.alertStore = alerts.NewStore(nil)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	// Fill up rate limit.
	for i := 0; i < maxCommandsPerMinute; i++ {
		h.allowCommand(42)
	}

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/help",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ===========================================================================
// ServeHTTP — unknown command
// ===========================================================================

func TestServeHTTP_UnknownCommandStartCommand(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/start",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected help/start message to be sent")
	}
}

// ===========================================================================
// ServeHTTP — /watchlist command (backward compat for /prices)
// ===========================================================================

func TestServeHTTP_WatchlistCommand(t *testing.T) {
	email := "user@test.com"
	fakeAPI := newFakeKiteAPI()
	defer fakeAPI.close()

	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:INFY": map[string]interface{}{
			"last_price": 1500.0,
			"ohlc": map[string]interface{}{
				"open": 0.0, "high": 0.0, "low": 0.0, "close": 1480.0,
			},
		},
	}

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.apiKeys[email] = "key"
	mgr.accessTokens[email] = "token"
	mgr.tokenValid[email] = true

	h, mock := newTestBotHandler(mgr)
	h.kiteBaseURI = fakeAPI.server.URL
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/watchlist INFY",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected watchlist/prices message to be sent")
	}
}

// ===========================================================================
// handlePrices — edge cases
// ===========================================================================

func TestHandlePrices_AllWhitespace2(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	result := h.handlePrices(42, email, "  ,  ,  ")
	if !strings.Contains(result, "No valid symbols") {
		t.Errorf("expected 'No valid symbols', got: %s", result)
	}
}

// ===========================================================================
// cancelPendingOrder path
// ===========================================================================

func TestCancelPendingOrder(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.setPendingOrder(42, &pendingOrder{
		Email:     email,
		CreatedAt: time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-cancel",
		Message: &tgbotapi.Message{
			MessageID: 800,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	h.cancelPendingOrder(42, cq)

	// Verify order was consumed.
	if got := h.popPendingOrder(42); got != nil {
		t.Error("expected pending order to be consumed after cancel")
	}
}

func TestCancelPendingOrder_NilMessage(t *testing.T) {
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	cq := &tgbotapi.CallbackQuery{
		ID:      "cb-cancel-nil",
		Message: nil,
	}

	// Should not panic.
	h.cancelPendingOrder(42, cq)
}

// ===========================================================================
// handleSetAlert — percentage direction > 100% rejection
// ===========================================================================

func TestHandleSetAlert_PercentageOver100(t *testing.T) {
	mgr := newMockKiteManager()
	mgr.instrMgr = newTestInstrumentsManager(t)
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE drop_pct 150")
	if !strings.Contains(result, "exceed 100%") {
		t.Errorf("expected '100%%' error, got: %s", result)
	}
}

func TestHandleSetAlert_PercentageValid(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE rise_pct 5")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "5.00%") {
		t.Errorf("expected '5.00%%', got: %s", result)
	}
	if !strings.Contains(result, "rise_pct") {
		t.Errorf("expected 'rise_pct', got: %s", result)
	}
}

// ===========================================================================
// handleSetAlert — drop_pct direction with percentage display
// ===========================================================================

func TestHandleSetAlert_DropPct(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "INFY drop_pct 3")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "3.00%") {
		t.Errorf("expected '3.00%%', got: %s", result)
	}
}

// ===========================================================================
// handleSetAlert — BSE fallback path
// ===========================================================================

func TestHandleSetAlert_BSEFallback(t *testing.T) {
	email := "user@test.com"
	// Create instruments manager with only BSE instrument.
	bseData := map[uint32]*instruments.Instrument{
		500325: {
			ID:              "BSE:RELIANCE",
			InstrumentToken: 500325,
			Tradingsymbol:   "RELIANCE",
			Exchange:        "BSE",
			Name:            "Reliance Industries",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	im, err := instruments.New(instruments.Config{
		TestData: bseData,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("instruments.New failed: %v", err)
	}

	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = im

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE above 2800")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "BSE") {
		t.Errorf("expected 'BSE' in result (fallback), got: %s", result)
	}
}

// ===========================================================================
// handleMyWatchlist — items with target entry/exit and valid LTP
// ===========================================================================

func TestHandleMyWatchlist_WithTargets(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	store := watchlist.NewStore()
	wlID, err := store.CreateWatchlist(email, "Targets WL")
	if err != nil {
		t.Fatalf("failed to create watchlist: %v", err)
	}
	_ = store.AddItem(email, wlID, &watchlist.WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
		TargetEntry:   2600.0,
		TargetExit:    3000.0,
	})

	// GetLTP in gokiteconnect v4.4.0 uses /quote endpoint (not /quote/ltp).
	fakeAPI.responses["/quote"] = map[string]interface{}{
		"NSE:RELIANCE": map[string]interface{}{
			"last_price": 2800.0,
		},
	}

	mgr := h.manager.(*mockKiteManager)
	mgr.watchlistStore = store

	result := h.handleMyWatchlist(42, email)
	if !strings.Contains(result, "RELIANCE") {
		t.Errorf("expected 'RELIANCE', got: %s", result)
	}
	if !strings.Contains(result, "2800.00") {
		t.Errorf("expected LTP '2800.00', got: %s", result)
	}
	if !strings.Contains(result, "entry") {
		t.Errorf("expected 'entry' target, got: %s", result)
	}
	if !strings.Contains(result, "exit") {
		t.Errorf("expected 'exit' target, got: %s", result)
	}
}

// ===========================================================================
// ServeHTTP — /buy and /sell command integration (covers the nil-reply path)
// ===========================================================================

func TestServeHTTP_BuyCommandIntegration(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/buy RELIANCE 10",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected confirmation message to be sent")
	}
}

func TestServeHTTP_SellCommandIntegration(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/sell INFY 5 1500",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected confirmation message to be sent")
	}
}

func TestServeHTTP_QuickCommandIntegration(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/quick RELIANCE 10 BUY MARKET",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected confirmation message to be sent")
	}
}

func TestServeHTTP_SetAlertCommandIntegration(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/setalert RELIANCE above 2700",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected alert set message to be sent")
	}
}

func TestServeHTTP_AlertsCommandIntegration(t *testing.T) {
	email := "user@test.com"
	store := alerts.NewStore(nil)
	store.Add(email, "RELIANCE", "NSE", 256265, 2700, alerts.DirectionAbove)

	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: email}}
	mgr.alertStore = store

	h, mock := newTestBotHandler(mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/alerts",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected alerts message to be sent")
	}
}

// ===========================================================================
// handleOrderCommand — paper trading mode label in confirmation
// ===========================================================================

func TestHandleBuy_PaperTradingMode(t *testing.T) {
	email := "user@test.com"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper2.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { paperDB.Close() })
	ptStore := papertrading.NewStore(paperDB, logger)
	ptStore.InitTables()
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000)

	mgr := newMockKiteManager()
	mgr.paperEngine = pe

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleBuy(42, email, "RELIANCE 10")
}

func TestHandleQuick_PaperTradingMode(t *testing.T) {
	email := "user@test.com"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper3.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { paperDB.Close() })
	ptStore := papertrading.NewStore(paperDB, logger)
	ptStore.InitTables()
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000)

	mgr := newMockKiteManager()
	mgr.paperEngine = pe

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "INFY 5 BUY LIMIT 1500")
}

// ===========================================================================
// ServeHTTP — confirm_order callback integration
// ===========================================================================

func TestServeHTTP_ConfirmOrderCallback(t *testing.T) {
	email := "user@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "ORD-CB-INT",
	}

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        5,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	update := tgbotapi.Update{
		CallbackQuery: &tgbotapi.CallbackQuery{
			ID:   "cb-confirm-int",
			Data: "confirm_order",
			From: &tgbotapi.User{ID: 42},
			Message: &tgbotapi.Message{
				MessageID: 1001,
				Chat:      &tgbotapi.Chat{ID: 42},
			},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
