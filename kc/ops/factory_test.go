package ops

// factory_test.go — Exercise DashboardHandler SUCCESS paths via injected
// KiteClientFactory. The SetKiteClientFactory injection point on Manager lets
// KiteClientFactory().NewClientWithToken() return a *kiteconnect.Client backed
// by an httptest server, covering dashboard API handlers end-to-end: market
// indices, portfolio, orders, alerts enrichment, sector exposure, tax analysis.

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ── mock KiteClientFactory ───────────────────────────────────────────────────

// testKiteClientFactory returns *kiteconnect.Client instances whose BaseURI
// points at the given mock server URL.
type testKiteClientFactory struct {
	mockURL string
}

func (f *testKiteClientFactory) NewClient(apiKey string) *kiteconnect.Client {
	c := kiteconnect.New(apiKey)
	c.SetBaseURI(f.mockURL)
	return c
}

func (f *testKiteClientFactory) NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client {
	c := kiteconnect.New(apiKey)
	c.SetAccessToken(accessToken)
	c.SetBaseURI(f.mockURL)
	return c
}

// ── mock Kite HTTP server for dashboard endpoints ────────────────────────────

func startDashboardMockKite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path

		env := func(data interface{}) string {
			b, _ := json.Marshal(map[string]interface{}{"status": "success", "data": data})
			return string(b)
		}

		switch {
		// user profile
		case p == "/user/profile":
			fmt.Fprint(w, env(map[string]any{
				"user_id": "DT1234", "user_name": "Dashboard User", "email": "dash@test.com",
			}))
		case strings.HasPrefix(p, "/user/margins"):
			fmt.Fprint(w, env(map[string]any{
				"equity": map[string]any{
					"enabled": true, "net": 500000.0,
					"available": map[string]any{"cash": 500000.0, "collateral": 0.0, "intraday_payin": 0.0},
					"utilised":  map[string]any{"debits": 0.0, "exposure": 0.0, "m2m_realised": 0.0, "m2m_unrealised": 0.0},
				},
			}))

		// portfolio
		case p == "/portfolio/holdings":
			fmt.Fprint(w, env([]map[string]any{
				{"tradingsymbol": "INFY", "exchange": "NSE", "isin": "INE009A01021", "quantity": 10, "average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0, "day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265},
				{"tradingsymbol": "RELIANCE", "exchange": "NSE", "isin": "INE002A01018", "quantity": 5, "average_price": 2500.0, "last_price": 2600.0, "pnl": 500.0, "day_change_percentage": 1.2, "product": "CNC", "instrument_token": 408065},
			}))
		case p == "/portfolio/positions":
			fmt.Fprint(w, env(map[string]any{
				"net": []map[string]any{
					{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 2, "average_price": 1550.0, "last_price": 1600.0, "pnl": 100.0, "product": "MIS"},
				},
				"day": []map[string]any{},
			}))

		// orders
		case p == "/orders" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "DASH-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))
		case strings.HasPrefix(p, "/orders/") && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "DASH-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))

		// trades
		case p == "/trades":
			fmt.Fprint(w, env([]map[string]any{
				{"trade_id": "T001", "order_id": "DASH-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0},
			}))

		// quote endpoints (used by market indices, alert enrichment)
		// NOTE: gokiteconnect SDK routes GetOHLC, GetLTP, and GetQuotes all
		// through /quote (URIGetQuote). The /quote/ohlc and /quote/ltp paths
		// are defined in the SDK but NOT used by the Go client methods.
		case p == "/quote":
			fmt.Fprint(w, env(map[string]any{
				"NSE:INFY":       map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
				"NSE:RELIANCE":   map[string]any{"instrument_token": 408065, "last_price": 2620.0, "ohlc": map[string]any{"open": 2580.0, "high": 2640.0, "low": 2570.0, "close": 2600.0}},
				"NSE:NIFTY 50":   map[string]any{"instrument_token": 100, "last_price": 22000.0, "ohlc": map[string]any{"open": 21900.0, "high": 22100.0, "low": 21800.0, "close": 21950.0}},
				"NSE:NIFTY BANK": map[string]any{"instrument_token": 200, "last_price": 48000.0, "ohlc": map[string]any{"open": 47800.0, "high": 48200.0, "low": 47700.0, "close": 47900.0}},
				"BSE:SENSEX":     map[string]any{"instrument_token": 300, "last_price": 72000.0, "ohlc": map[string]any{"open": 71800.0, "high": 72200.0, "low": 71700.0, "close": 71900.0}},
			}))
		// GTT
		case p == "/gtt/triggers" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{}))

		default:
			http.Error(w, `{"status":"error","message":"not found: `+p+`"}`, 404)
		}
	}))
}

// ── Dashboard + Manager setup with KiteClientFactory injection ───────────────

const dashTestEmail = "dash@test.com"

// newDashboardWithMockKite creates a DashboardHandler backed by a non-DevMode
// Manager whose KiteClientFactory has been replaced with one that routes
// all Kite API calls to the given mock server URL.
func newDashboardWithMockKite(t *testing.T, mockURL string) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}
	instrMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "dash_key",
		APISecret:          "dash_secret",
		Logger:             logger,
		InstrumentsManager: instrMgr,
		DevMode:            false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	// Inject mock KiteClientFactory so all NewClientWithToken calls
	// return clients pointing at the httptest server.
	mgr.SetKiteClientFactory(&testKiteClientFactory{mockURL: mockURL})

	// Seed credentials + tokens so dashboard handlers find them.
	mgr.CredentialStore().Set(dashTestEmail, &kc.KiteCredentialEntry{
		APIKey: "dash_key", APISecret: "dash_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set(dashTestEmail, &kc.KiteTokenEntry{
		AccessToken: "dash-access-token", StoredAt: time.Now(),
	})

	d := NewDashboardHandler(mgr, logger, nil)
	d.SetAdminCheck(func(email string) bool { return false })
	return d
}

// dashRequest creates an HTTP request with the test email in context.
func dashRequest(method, target string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	ctx := oauth.ContextWithEmail(req.Context(), dashTestEmail)
	return req.WithContext(ctx)
}

// ── Tests: dashboard API success paths via KiteClientFactory ─────────────────

func TestFactoryDash_MarketIndices(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/market-indices"))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should contain NIFTY 50, NIFTY BANK, SENSEX
	assert.Contains(t, result, "NSE:NIFTY 50")
	assert.Contains(t, result, "NSE:NIFTY BANK")
	assert.Contains(t, result, "BSE:SENSEX")
}

func TestFactoryDash_Portfolio(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/portfolio"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have holdings and positions
	assert.Contains(t, result, "holdings")
	assert.Contains(t, result, "positions")
	assert.Contains(t, result, "summary")
}

func TestFactoryDash_SectorExposure(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/sector-exposure"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have sectors array
	assert.Contains(t, result, "sectors")
}

func TestFactoryDash_TaxAnalysis(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/tax-analysis"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	// Should have holdings array
	assert.Contains(t, result, "holdings")
}

func TestFactoryDash_Status(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/status"))

	assert.Equal(t, http.StatusOK, rec.Code)

	var result map[string]any
	err := json.NewDecoder(rec.Body).Decode(&result)
	require.NoError(t, err)
	assert.Equal(t, dashTestEmail, result["email"])
}

// ── Negative tests: no credentials / no token ────────────────────────────────

func TestFactoryDash_MarketIndices_NoCreds(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	// Remove credentials to trigger the no-creds path
	d.manager.CredentialStore().Delete(dashTestEmail)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/market-indices"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFactoryDash_Portfolio_NoToken(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	// Remove token to trigger the no-token path
	d.manager.TokenStore().Delete(dashTestEmail)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, dashRequest(http.MethodGet, "/dashboard/api/portfolio"))

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestFactoryDash_Portfolio_NoAuth(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()
	d := newDashboardWithMockKite(t, ts.URL)

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Request with no email in context
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/portfolio", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ── KiteClientFactory unit test ──────────────────────────────────────────────

func TestKiteClientFactory_NewClientWithToken(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()

	factory := &testKiteClientFactory{mockURL: ts.URL}
	client := factory.NewClientWithToken("key", "token")
	assert.NotNil(t, client)

	// Verify the mock server handles profile requests
	profile, err := client.GetUserProfile()
	require.NoError(t, err)
	assert.Equal(t, "DT1234", profile.UserID)
}

func TestKiteClientFactory_NewClient(t *testing.T) {
	t.Parallel()
	ts := startDashboardMockKite()
	defer ts.Close()

	factory := &testKiteClientFactory{mockURL: ts.URL}
	client := factory.NewClient("key")
	assert.NotNil(t, client)

	// GetHoldings should work against mock
	holdings, err := client.GetHoldings()
	require.NoError(t, err)
	assert.Len(t, holdings, 2)
}
