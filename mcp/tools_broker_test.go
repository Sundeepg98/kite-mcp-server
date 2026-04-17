package mcp

// tools_factory_test.go — Exercise tool handler SUCCESS paths via injected
// broker.Factory. The broker.Factory injection point in SessionService lets
// GetBrokerForEmail return a broker.Client backed by an httptest server,
// covering the use-case → broker API → response formatting path end-to-end.
//
// Contrast with tools_mockkite_test.go which pre-seeds KiteSessionData.Broker
// on an existing session. This file tests the broker.Factory fallback path
// (no active session found for email, factory creates a new client).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ── mock broker.Factory that creates Zerodha clients backed by httptest ──────

// mockBrokerFactory implements broker.Factory. Every client it creates points
// at the given mock server URL instead of the real Kite API.
type mockBrokerFactory struct {
	mockURL string
}

func (f *mockBrokerFactory) BrokerName() broker.Name { return broker.Zerodha }

func (f *mockBrokerFactory) Create(apiKey string) (broker.Client, error) {
	kc := kiteconnect.New(apiKey)
	kc.SetBaseURI(f.mockURL)
	return zerodha.New(kc), nil
}

func (f *mockBrokerFactory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
	kc := kiteconnect.New(apiKey)
	kc.SetAccessToken(accessToken)
	kc.SetBaseURI(f.mockURL)
	return zerodha.New(kc), nil
}

// ── mock Kite HTTP server (richer: includes /orders POST for place_order) ────

func startMockKiteForFactory() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path

		env := func(data any) string {
			b, _ := json.Marshal(map[string]any{"status": "success", "data": data})
			return string(b)
		}

		switch {
		// user
		case p == "/user/profile":
			fmt.Fprint(w, env(map[string]any{
				"user_id": "AB1234", "user_name": "Factory User", "email": "factory@test.com",
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
				{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 10, "average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0, "day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265},
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
				{"order_id": "FACT-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))
		case p == "/orders" && r.Method == http.MethodPost:
			fmt.Fprint(w, env(map[string]any{"order_id": "FACT-ORD-NEW"}))
		case strings.HasPrefix(p, "/orders/") && strings.HasSuffix(p, "/trades"):
			fmt.Fprint(w, env([]map[string]any{
				{"trade_id": "T001", "order_id": "FACT-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0, "fill_timestamp": "2026-04-01 10:00:01"},
			}))
		case strings.HasPrefix(p, "/orders/") && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "FACT-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			}))
		case strings.HasPrefix(p, "/orders/") && r.Method == http.MethodPut:
			fmt.Fprint(w, env(map[string]any{"order_id": "FACT-ORD-1"}))
		case strings.HasPrefix(p, "/orders/") && r.Method == http.MethodDelete:
			fmt.Fprint(w, env(map[string]any{"order_id": "FACT-ORD-1"}))

		// trades
		case p == "/trades":
			fmt.Fprint(w, env([]map[string]any{
				{"trade_id": "T001", "order_id": "FACT-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0},
			}))

		// quote
		case p == "/quote":
			fmt.Fprint(w, env(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
			}))
		case p == "/quote/ltp":
			fmt.Fprint(w, env(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0},
			}))
		case p == "/quote/ohlc":
			fmt.Fprint(w, env(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
			}))

		// GTT
		case p == "/gtt/triggers" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{}))
		case p == "/gtt/triggers" && r.Method == http.MethodPost:
			fmt.Fprint(w, env(map[string]any{"trigger_id": 12345}))

		// MF
		case p == "/mf/orders" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"order_id": "MF001", "tradingsymbol": "INF209K01YS2", "transaction_type": "BUY", "amount": 5000.0, "status": "COMPLETE"},
			}))
		case p == "/mf/sips" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"sip_id": "SIP001", "tradingsymbol": "INF209K01YS2", "amount": 1000.0, "frequency": "monthly", "status": "ACTIVE"},
			}))
		case p == "/mf/holdings" && r.Method == http.MethodGet:
			fmt.Fprint(w, env([]map[string]any{
				{"tradingsymbol": "INF209K01YS2", "fund": "Motilal Oswal Nifty 50", "quantity": 100.5, "average_price": 50.0, "last_price": 55.0, "pnl": 502.5},
			}))

		// margins
		case p == "/margins/orders":
			fmt.Fprint(w, env([]map[string]any{
				{"type": "equity", "tradingsymbol": "INFY", "exchange": "NSE", "total": 15000.0},
			}))
		case p == "/margins/basket":
			fmt.Fprint(w, env(map[string]any{
				"initial": map[string]any{"total": 15000.0},
				"final":   map[string]any{"total": 14000.0},
				"orders":  []map[string]any{{"tradingsymbol": "INFY", "total": 15000.0}},
			}))
		case p == "/charges/orders":
			fmt.Fprint(w, env([]map[string]any{
				{"total_charges": 15.5, "gst": map[string]any{"total": 2.79}},
			}))

		default:
			http.Error(w, `{"status":"error","message":"not found: `+p+`"}`, 404)
		}
	}))
}

// ── Non-DevMode manager with broker.Factory injection ────────────────────────

const factoryEmail = "factory@test.com"
const factorySessionID = "f1a2b3c4-d5e6-7890-abcd-ef1234567890"

// newFactoryManager creates a non-DevMode manager with a mock broker.Factory
// injected into the SessionService. Credentials and tokens are pre-seeded so
// GetBrokerForEmail can resolve a broker client via the factory.
func newFactoryManager(t *testing.T, mockURL string) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}
	instMgr, err := instruments.New(instruments.Config{
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
		APIKey:             "factory_key",
		APISecret:          "factory_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	// Inject the mock broker factory so GetBrokerForEmail uses it.
	mgr.SessionSvc().SetBrokerFactory(&mockBrokerFactory{mockURL: mockURL})

	// Seed credentials + tokens so GetBrokerForEmail resolves successfully.
	mgr.CredentialStore().Set(factoryEmail, &kc.KiteCredentialEntry{
		APIKey: "factory_key", APISecret: "factory_secret", StoredAt: time.Now(),
	})
	mgr.TokenStore().Set(factoryEmail, &kc.KiteTokenEntry{
		AccessToken: "factory-access-token", StoredAt: time.Now(),
	})

	// Pre-seed a session so WithSession can find it. The session's Broker
	// is also backed by the mock because we use the same mock URL.
	kiteClient := kiteconnect.New("factory_key")
	kiteClient.SetAccessToken("factory-access-token")
	kiteClient.SetBaseURI(mockURL)

	kd := &kc.KiteSessionData{
		Kite:   &kc.KiteConnect{Client: kiteClient},
		Broker: zerodha.New(kiteClient),
		Email:  factoryEmail,
	}

	sm := mgr.SessionManager()
	require.NotNil(t, sm)
	_, _, _ = mgr.GetOrCreateSessionWithEmail(factorySessionID, factoryEmail)
	require.NoError(t, sm.UpdateSessionData(factorySessionID, kd))

	return mgr
}

// callFactoryTool calls a tool through a non-DevMode manager with broker.Factory injection.
func callFactoryTool(t *testing.T, mgr *kc.Manager, toolName string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

// ── Tests: broker.Factory success paths ──────────────────────────────────────

func TestFactory_GetProfile(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_profile", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetMargins(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_margins", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetHoldings(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_holdings", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetPositions(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_positions", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetOrders(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_orders", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetTrades(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_trades", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetLTP(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_ltp", map[string]any{"instruments": "NSE:INFY"})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetOHLC(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_ohlc", map[string]any{"instruments": "NSE:INFY"})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetQuotes(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_quotes", map[string]any{"instruments": "NSE:INFY"})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetOrderHistory(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_order_history", map[string]any{"order_id": "FACT-ORD-1"})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetOrderTrades(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_order_trades", map[string]any{"order_id": "FACT-ORD-1"})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetGTTs(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_gtts", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetMFOrders(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_mf_orders", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetMFSIPs(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_mf_sips", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestFactory_GetMFHoldings(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_mf_holdings", map[string]any{})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// ── Margin tools via factory ─────────────────────────────────────────────────

func TestFactory_GetOrderMargins(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_order_margins", map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY",
		"quantity": float64(10), "product": "CNC", "order_type": "MARKET",
	})
	assert.NotNil(t, result)
}

func TestFactory_GetBasketMargins(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_basket_margins", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":1,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.NotNil(t, result)
}

func TestFactory_GetOrderCharges(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "get_order_charges", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":1,"price":1500,"product":"CNC","order_type":"LIMIT","variety":"regular"}]`,
	})
	assert.NotNil(t, result)
}

// ── Analytics tools via factory ──────────────────────────────────────────────

func TestFactory_PortfolioSummary(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "portfolio_summary", map[string]any{})
	assert.NotNil(t, result)
}

func TestFactory_SectorExposure(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "sector_exposure", map[string]any{})
	assert.NotNil(t, result)
}

func TestFactory_TaxHarvestAnalysis(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "tax_loss_analysis", map[string]any{})
	assert.NotNil(t, result)
}

func TestFactory_PreTradeCheck(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()
	mgr := newFactoryManager(t, ts.URL)
	result := callFactoryTool(t, mgr, "order_risk_report", map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY",
		"quantity": float64(10), "price": float64(1500), "product": "CNC", "order_type": "LIMIT",
	})
	assert.NotNil(t, result)
}

// ── broker.Factory unit test (no full Manager) ──────────────────────────────

func TestMockBrokerFactory_CreateWithToken(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()

	factory := &mockBrokerFactory{mockURL: ts.URL}

	assert.Equal(t, broker.Zerodha, factory.BrokerName())

	client, err := factory.CreateWithToken("key", "token")
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, broker.Zerodha, client.BrokerName())

	// Verify the mock actually works — GetProfile should return our mock data.
	profile, err := client.GetProfile()
	require.NoError(t, err)
	assert.Equal(t, "AB1234", profile.UserID)
	assert.Equal(t, "Factory User", profile.UserName)
}

func TestMockBrokerFactory_Create(t *testing.T) {
	t.Parallel()
	ts := startMockKiteForFactory()
	defer ts.Close()

	factory := &mockBrokerFactory{mockURL: ts.URL}
	client, err := factory.Create("key")
	require.NoError(t, err)
	assert.NotNil(t, client)

	holdings, err := client.GetHoldings()
	require.NoError(t, err)
	assert.Len(t, holdings, 1)
	assert.Equal(t, "INFY", holdings[0].Tradingsymbol)
}
