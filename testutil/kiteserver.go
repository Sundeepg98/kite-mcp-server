// Package testutil provides shared test infrastructure for the kite-mcp-server
// project. It is NOT a _test.go file so that any package can import it.
package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// MockKiteServer wraps an httptest.Server that simulates the Kite Connect API.
// Tests configure responses via the Set* methods and then point a
// kiteconnect.Client at Server.URL.
//
// IMPORTANT: The gokiteconnect SDK routes GetLTP(), GetOHLC(), and GetQuotes()
// all through the /quote endpoint (not /quote/ltp or /quote/ohlc). This mock
// handles /quote as the primary route. The /quote/ltp and /quote/ohlc paths
// are registered as aliases for direct HTTP testing convenience.
type MockKiteServer struct {
	Server *httptest.Server

	mu        sync.RWMutex
	profile   any
	holdings  any
	positions any
	orders    any
	trades    any
	quotes    any // combined quote data — served on /quote (SDK uses this for LTP, OHLC, full quotes)
	trigger   any
	mfOrders  any
	mfSIPs    any
	mfHoldings any
	margins   any
	orderMargins any
	basketMargins any
}

// NewMockKiteServer creates a mock Kite HTTP server with realistic default
// responses for all required endpoints. The server is automatically closed
// when the test finishes.
func NewMockKiteServer(t *testing.T) *MockKiteServer {
	t.Helper()

	m := &MockKiteServer{}
	m.setDefaults()

	mux := http.NewServeMux()
	m.registerRoutes(mux)

	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Server.Close)

	return m
}

// NewSessionKiteServer returns a bare *httptest.Server that handles the Kite
// session lifecycle routes (POST /session/token, GET /user/profile, DELETE
// /session/token) plus all default MockKiteServer data routes. It is the
// shared replacement for per-package newMockKiteServer helpers that test the
// GenerateSession → CompleteSession → InvalidateAccessToken flow.
//
// The server is automatically closed when the test finishes.
func NewSessionKiteServer(t *testing.T) *httptest.Server {
	t.Helper()

	m := &MockKiteServer{}
	m.setDefaults()

	mux := http.NewServeMux()
	m.registerRoutes(mux)

	// Session lifecycle routes — not part of the read-only MockKiteServer core.
	mux.HandleFunc("/session/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			writeEnvelope(w, map[string]any{
				"user_id":       "XY1234",
				"user_name":     "Test User",
				"email":         "test@example.com",
				"access_token":  "mock-access-token",
				"public_token":  "mock-public-token",
				"refresh_token": "mock-refresh-token",
			})
		case http.MethodDelete:
			writeEnvelope(w, true)
		default:
			http.Error(w, `{"status":"error","message":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// URL returns the base URL of the mock server.
func (m *MockKiteServer) URL() string {
	return m.Server.URL
}

// Client creates a kiteconnect.Client pointed at this mock server.
func (m *MockKiteServer) Client(apiKey, accessToken string) *kiteconnect.Client {
	kc := kiteconnect.New(apiKey)
	kc.SetBaseURI(m.Server.URL)
	kc.SetAccessToken(accessToken)
	return kc
}

// ---------------------------------------------------------------------------
// Setters — tests call these to configure responses before exercising code
// ---------------------------------------------------------------------------

func (m *MockKiteServer) SetProfile(v any)        { m.mu.Lock(); m.profile = v; m.mu.Unlock() }
func (m *MockKiteServer) SetHoldings(v any)        { m.mu.Lock(); m.holdings = v; m.mu.Unlock() }
func (m *MockKiteServer) SetPositions(v any)       { m.mu.Lock(); m.positions = v; m.mu.Unlock() }
func (m *MockKiteServer) SetOrders(v any)          { m.mu.Lock(); m.orders = v; m.mu.Unlock() }
func (m *MockKiteServer) SetTrades(v any)          { m.mu.Lock(); m.trades = v; m.mu.Unlock() }
func (m *MockKiteServer) SetQuotes(v any)          { m.mu.Lock(); m.quotes = v; m.mu.Unlock() }
func (m *MockKiteServer) SetTriggerRange(v any)    { m.mu.Lock(); m.trigger = v; m.mu.Unlock() }
func (m *MockKiteServer) SetMFOrders(v any)        { m.mu.Lock(); m.mfOrders = v; m.mu.Unlock() }
func (m *MockKiteServer) SetMFSIPs(v any)          { m.mu.Lock(); m.mfSIPs = v; m.mu.Unlock() }
func (m *MockKiteServer) SetMFHoldings(v any)      { m.mu.Lock(); m.mfHoldings = v; m.mu.Unlock() }
func (m *MockKiteServer) SetMargins(v any)         { m.mu.Lock(); m.margins = v; m.mu.Unlock() }
func (m *MockKiteServer) SetOrderMargins(v any)    { m.mu.Lock(); m.orderMargins = v; m.mu.Unlock() }
func (m *MockKiteServer) SetBasketMargins(v any)   { m.mu.Lock(); m.basketMargins = v; m.mu.Unlock() }

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

func (m *MockKiteServer) registerRoutes(mux *http.ServeMux) {
	// User
	mux.HandleFunc("/user/profile", m.handle(func() any { return m.profile }))

	// Portfolio
	mux.HandleFunc("/portfolio/holdings", m.handle(func() any { return m.holdings }))
	mux.HandleFunc("/portfolio/positions", m.handle(func() any { return m.positions }))

	// Orders & trades
	mux.HandleFunc("/orders", m.handle(func() any { return m.orders }))
	mux.HandleFunc("/trades", m.handle(func() any { return m.trades }))

	// Quotes — gokiteconnect SDK routes GetLTP/GetOHLC/GetQuotes all through /quote.
	// /quote/ltp and /quote/ohlc are registered as aliases for direct HTTP tests.
	quoteHandler := m.handle(func() any { return m.quotes })
	mux.HandleFunc("/quote", quoteHandler)
	mux.HandleFunc("/quote/ltp", quoteHandler)
	mux.HandleFunc("/quote/ohlc", quoteHandler)

	// Instruments
	mux.HandleFunc("/instruments/", m.handleInstruments())

	// Mutual funds
	mux.HandleFunc("/mf/orders", m.handle(func() any { return m.mfOrders }))
	mux.HandleFunc("/mf/sips", m.handle(func() any { return m.mfSIPs }))
	mux.HandleFunc("/mf/holdings", m.handle(func() any { return m.mfHoldings }))

	// Margins
	mux.HandleFunc("/user/margins", m.handle(func() any { return m.margins }))
	mux.HandleFunc("/margins/orders", m.handle(func() any { return m.orderMargins }))
	mux.HandleFunc("/margins/basket", m.handle(func() any { return m.basketMargins }))
}

// ---------------------------------------------------------------------------
// Handler helpers
// ---------------------------------------------------------------------------

// handle creates a handler that returns the Kite JSON envelope for the given data getter.
func (m *MockKiteServer) handle(getData func() any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.RLock()
		data := getData()
		m.mu.RUnlock()

		writeEnvelope(w, data)
	}
}

// handleInstruments handles /instruments/{exchange}/{tradingsymbol}/trigger_range
// and falls back to the trigger range response.
func (m *MockKiteServer) handleInstruments() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/trigger_range") {
			m.mu.RLock()
			data := m.trigger
			m.mu.RUnlock()
			writeEnvelope(w, data)
			return
		}
		// Fallback: empty CSV for /instruments or /instruments/{exchange}
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
	}
}

// writeEnvelope writes the Kite API JSON envelope: {"status":"success","data":...}
func writeEnvelope(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]any{
		"status": "success",
		"data":   data,
	}
	json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// Realistic default data
// ---------------------------------------------------------------------------

func (m *MockKiteServer) setDefaults() {
	m.profile = map[string]any{
		"user_id":        "AB1234",
		"user_name":      "Test User",
		"user_shortname": "TU",
		"email":          "test@example.com",
		"user_type":      "individual",
		"broker":         "ZERODHA",
		"exchanges":      []string{"NSE", "BSE", "NFO", "MCX"},
		"products":       []string{"CNC", "NRML", "MIS", "BO", "CO"},
		"order_types":    []string{"MARKET", "LIMIT", "SL", "SL-M"},
		"meta":           map[string]any{"demat_consent": "physical"},
	}

	m.holdings = []map[string]any{
		{
			"tradingsymbol":       "INFY",
			"exchange":            "NSE",
			"instrument_token":    256265,
			"isin":                "INE009A01021",
			"product":             "CNC",
			"price":               1500.0,
			"quantity":            10,
			"used_quantity":       0,
			"t1_quantity":         0,
			"realised_quantity":   10,
			"authorised_quantity": 0,
			"average_price":       1400.0,
			"last_price":          1550.0,
			"close_price":         1520.0,
			"pnl":                 1500.0,
			"day_change":          30.0,
			"day_change_percentage": 1.97,
			"opening_quantity":    10,
			"collateral_quantity": 0,
			"collateral_type":    "",
			"discrepancy":        false,
		},
	}

	m.positions = map[string]any{
		"net": []map[string]any{
			{
				"tradingsymbol":   "SBIN",
				"exchange":        "NSE",
				"instrument_token": 779521,
				"product":         "MIS",
				"quantity":        5,
				"average_price":   620.0,
				"last_price":      625.0,
				"pnl":            25.0,
			},
		},
		"day": []map[string]any{
			{
				"tradingsymbol":   "SBIN",
				"exchange":        "NSE",
				"instrument_token": 779521,
				"product":         "MIS",
				"quantity":        5,
				"average_price":   620.0,
				"last_price":      625.0,
				"pnl":            25.0,
			},
		},
	}

	m.orders = []map[string]any{
		{
			"order_id":        "220101000000001",
			"exchange":        "NSE",
			"tradingsymbol":   "RELIANCE",
			"transaction_type": "BUY",
			"order_type":      "LIMIT",
			"product":         "CNC",
			"quantity":        1.0,
			"price":           2500.0,
			"trigger_price":   0.0,
			"status":          "COMPLETE",
			"filled_quantity":  1.0,
			"average_price":   2500.0,
			"variety":         "regular",
			"validity":        "DAY",
		},
	}

	m.trades = []map[string]any{
		{
			"trade_id":         "T001",
			"order_id":         "220101000000001",
			"exchange":         "NSE",
			"tradingsymbol":    "RELIANCE",
			"transaction_type": "BUY",
			"quantity":         1.0,
			"price":            2500.0,
			"product":          "CNC",
		},
	}

	// quotes is the combined response served on /quote. The gokiteconnect SDK
	// extracts LTP, OHLC, and full quote data from this same response.
	m.quotes = map[string]any{
		"NSE:INFY": map[string]any{
			"instrument_token": 256265,
			"last_price":       1550.0,
			"ohlc": map[string]any{
				"open":  1520.0,
				"high":  1560.0,
				"low":   1510.0,
				"close": 1530.0,
			},
		},
		"NSE:RELIANCE": map[string]any{
			"instrument_token": 408065,
			"last_price":       2550.0,
			"ohlc": map[string]any{
				"open":  2520.0,
				"high":  2580.0,
				"low":   2500.0,
				"close": 2540.0,
			},
		},
		"NSE:NIFTY 50": map[string]any{
			"instrument_token": 100,
			"last_price":       22000.0,
			"ohlc": map[string]any{
				"open":  21900.0,
				"high":  22100.0,
				"low":   21800.0,
				"close": 21950.0,
			},
		},
		"NSE:NIFTY BANK": map[string]any{
			"instrument_token": 200,
			"last_price":       48000.0,
			"ohlc": map[string]any{
				"open":  47800.0,
				"high":  48200.0,
				"low":   47700.0,
				"close": 47900.0,
			},
		},
		"BSE:SENSEX": map[string]any{
			"instrument_token": 300,
			"last_price":       72000.0,
			"ohlc": map[string]any{
				"open":  71800.0,
				"high":  72200.0,
				"low":   71700.0,
				"close": 71900.0,
			},
		},
	}

	m.trigger = map[string]any{
		"NSE:INFY": map[string]any{
			"instrument_token": 256265,
			"lower":            1400.0,
			"upper":            1700.0,
			"percentage":       5.0,
		},
	}

	m.mfOrders = []map[string]any{
		{
			"order_id":          "MF001",
			"tradingsymbol":     "INF090I01239",
			"status":            "COMPLETE",
			"transaction_type":  "BUY",
			"amount":            5000.0,
		},
	}

	m.mfSIPs = []map[string]any{
		{
			"sip_id":            "SIP001",
			"tradingsymbol":     "INF090I01239",
			"fund":              "HDFC Liquid Fund",
			"frequency":         "monthly",
			"instalment_amount": 5000.0,
			"status":            "ACTIVE",
		},
	}

	m.mfHoldings = []map[string]any{
		{
			"tradingsymbol": "INF090I01239",
			"fund":          "HDFC Liquid Fund",
			"average_price": 100.0,
			"last_price":    105.0,
			"quantity":      50.0,
			"pnl":           250.0,
		},
	}

	m.margins = map[string]any{
		"equity": map[string]any{
			"enabled": true,
			"net":     100000.0,
			"available": map[string]any{
				"cash":            80000.0,
				"collateral":      10000.0,
				"live_balance":    90000.0,
				"opening_balance": 100000.0,
			},
			"utilised": map[string]any{
				"debits":   5000.0,
				"exposure": 2000.0,
			},
		},
		"commodity": map[string]any{
			"enabled": false,
			"net":     0.0,
			"available": map[string]any{
				"cash": 0.0,
			},
			"utilised": map[string]any{},
		},
	}

	m.orderMargins = []map[string]any{
		{
			"type":       "equity",
			"tradingsymbol": "INFY",
			"exchange":   "NSE",
			"total":      15000.0,
			"var":        5000.0,
			"span":       0.0,
			"exposure":   10000.0,
		},
	}

	m.basketMargins = map[string]any{
		"initial": map[string]any{
			"total": 15000.0,
		},
		"final": map[string]any{
			"total": 12000.0,
		},
		"orders": []map[string]any{
			{
				"total": 15000.0,
			},
		},
	}
}
