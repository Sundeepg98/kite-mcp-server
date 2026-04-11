package papertrading

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// mockLTP implements LTPProvider with fixed prices.
type mockLTP struct {
	prices map[string]float64
}

func (m *mockLTP) GetLTP(instruments ...string) (map[string]float64, error) {
	result := make(map[string]float64)
	for _, inst := range instruments {
		if p, ok := m.prices[inst]; ok {
			result[inst] = p
		}
	}
	return result, nil
}

// testEngine creates an in-memory-backed PaperEngine with a mock LTP provider.
func testEngine(t *testing.T, prices map[string]float64) *PaperEngine {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: prices})
	return engine
}

const testEmail = "test@example.com"

func TestEnableDisable(t *testing.T) {
	engine := testEngine(t, nil)

	// Not enabled initially.
	assert.False(t, engine.IsEnabled(testEmail))

	// Enable with 1M cash.
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	assert.True(t, engine.IsEnabled(testEmail))

	// Account has correct cash.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.Equal(t, 1_000_000.0, acct.CashBalance)
	assert.Equal(t, 1_000_000.0, acct.InitialCash)

	// Disable.
	require.NoError(t, engine.Disable(testEmail))
	assert.False(t, engine.IsEnabled(testEmail))

	// Account still exists but is disabled.
	acct, err = engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.NotNil(t, acct)
	assert.False(t, acct.Enabled)
}

func TestPlaceMarketOrder(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:RELIANCE": 2500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])

	// Cash should be deducted: 1M - 10*2500 = 975000.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.InDelta(t, 975_000.0, acct.CashBalance, 0.01)

	// Position should exist.
	positions, err := engine.store.GetPositions(testEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, "RELIANCE", positions[0].Tradingsymbol)
	assert.Equal(t, 10, positions[0].Quantity)
	assert.InDelta(t, 2500.0, positions[0].AveragePrice, 0.01)
}

func TestPlaceLimitOrder(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:INFY": 1500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Limit BUY at 1400 — not marketable (LTP is 1500).
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         5,
		"price":            1400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// No position should exist yet.
	positions, err := engine.store.GetPositions(testEmail)
	require.NoError(t, err)
	assert.Empty(t, positions)

	// Order should be in OPEN state.
	orders, err := engine.store.GetOpenOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "OPEN", orders[0].Status)
	assert.Equal(t, "LIMIT", orders[0].OrderType)
	assert.InDelta(t, 1400.0, orders[0].Price, 0.01)
}

func TestCancelOrder(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:TCS": 3500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a limit order that stays OPEN.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         2,
		"price":            3400.0,
	})
	require.NoError(t, err)
	orderID := result["order_id"].(string)
	assert.Equal(t, "OPEN", result["status"])

	// Cancel it.
	cancelResult, err := engine.CancelOrder(testEmail, orderID)
	require.NoError(t, err)
	assert.Equal(t, "CANCELLED", cancelResult["status"])

	// Verify it's no longer OPEN.
	openOrders, err := engine.store.GetOpenOrders(testEmail)
	require.NoError(t, err)
	assert.Empty(t, openOrders)
}

func TestInsufficientCash(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:RELIANCE": 2500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 10_000)) // Only 10K

	// Try to buy 10 shares at 2500 = 25000 > 10000 cash.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])

	// Cash should be unchanged.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.InDelta(t, 10_000.0, acct.CashBalance, 0.01)
}

func TestSellOrder(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:SBIN": 800.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// BUY first.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	cashAfterBuy, _ := engine.store.GetAccount(testEmail)
	assert.InDelta(t, 920_000.0, cashAfterBuy.CashBalance, 0.01) // 1M - 100*800

	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// SELL 50.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "SELL",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         50,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])

	// Cash should increase: 920000 + 50*800 = 960000.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.InDelta(t, 960_000.0, acct.CashBalance, 0.01)

	// Position should be reduced to 50.
	positions, err := engine.store.GetPositions(testEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, 50, positions[0].Quantity)
}

func TestGetHoldings(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:HDFC": 1600.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// BUY CNC — should create holding.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "HDFC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         20,
	})
	require.NoError(t, err)

	holdingsResp, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)

	holdings := holdingsResp.([]map[string]any)
	require.Len(t, holdings, 1)
	assert.Equal(t, "HDFC", holdings[0]["tradingsymbol"])
	assert.Equal(t, 20, holdings[0]["quantity"])
}

func TestGetPositions(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:ITC": 450.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "ITC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	posResp, err := engine.GetPositions(testEmail)
	require.NoError(t, err)

	posMap := posResp.(map[string]any)
	day := posMap["day"].([]map[string]any)
	require.Len(t, day, 1)
	assert.Equal(t, "ITC", day[0]["tradingsymbol"])
	assert.Equal(t, 100, day[0]["quantity"])
	assert.InDelta(t, 450.0, day[0]["average_price"], 0.01)
}

func TestGetMargins(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:WIPRO": 500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 500_000))

	// Buy some shares to reduce cash.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "WIPRO",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	marginsResp, err := engine.GetMargins(testEmail)
	require.NoError(t, err)

	margins := marginsResp.(map[string]any)
	equity := margins["equity"].(map[string]any)
	avail := equity["available"].(map[string]any)
	assert.InDelta(t, 450_000.0, avail["cash"], 0.01) // 500K - 100*500
	assert.InDelta(t, 500_000.0, equity["net"], 0.01)
}

func TestReset(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:RELIANCE": 2500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place an order so there's data.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Verify data exists.
	orders, _ := engine.store.GetOrders(testEmail)
	assert.NotEmpty(t, orders)
	holdings, _ := engine.store.GetHoldings(testEmail)
	assert.NotEmpty(t, holdings)

	// Reset.
	require.NoError(t, engine.Reset(testEmail))

	// All data cleared.
	orders, _ = engine.store.GetOrders(testEmail)
	assert.Empty(t, orders)
	positions, _ := engine.store.GetPositions(testEmail)
	assert.Empty(t, positions)
	holdings, _ = engine.store.GetHoldings(testEmail)
	assert.Empty(t, holdings)

	// Cash restored to initial.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_000_000.0, acct.CashBalance, 0.01)
}

// ===========================================================================
// Edge cases and error paths to push coverage above 95%
// ===========================================================================

func TestStatus_NotEnabled(t *testing.T) {
	engine := testEngine(t, nil)

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, false, status["enabled"])
	assert.Contains(t, status["message"], "not configured")
}

func TestStatus_Enabled(t *testing.T) {
	engine := testEngine(t, nil)
	require.NoError(t, engine.Enable(testEmail, 500_000))

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, true, status["enabled"])
	assert.Equal(t, 500_000.0, status["initial_cash"])
	assert.Equal(t, 500_000.0, status["cash_balance"])
	assert.Equal(t, 0, status["positions"])
	assert.Equal(t, 0, status["holdings"])
	assert.Equal(t, 0, status["open_orders"])
}

func TestStatus_WithOpenOrders(t *testing.T) {
	engine := testEngine(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a LIMIT order (stays OPEN since no LTP to fill).
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         10,
		"price":            1500.0,
	})
	require.NoError(t, err)

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, 1, status["open_orders"])
}

func TestGetMargins_NoAccount(t *testing.T) {
	engine := testEngine(t, nil)

	margins, err := engine.GetMargins(testEmail)
	require.NoError(t, err)
	// Should return zero-value margins for non-existent account.
	assert.NotNil(t, margins)
}

func TestGetMargins_Enabled(t *testing.T) {
	engine := testEngine(t, map[string]float64{
		"NSE:RELIANCE": 2500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place and fill an order to create positions.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	margins, err := engine.GetMargins(testEmail)
	require.NoError(t, err)
	assert.NotNil(t, margins)
}

func TestMonitor_FillLimitOrder(t *testing.T) {
	prices := map[string]float64{"NSE:SBIN": 600.0}
	engine := testEngine(t, prices)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a BUY LIMIT order at 610 (above current price 600, so it fills).
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "CNC",
		"quantity":         100,
		"price":            610.0,
	})
	require.NoError(t, err)

	// Start the monitor, which should pick up and fill the LIMIT order.
	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// After tick, the order should be COMPLETE.
	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "COMPLETE", orders[0].Status)
	assert.Equal(t, 100, orders[0].FilledQuantity)

	// Cash should be reduced.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.Less(t, acct.CashBalance, 1_000_000.0)

	// Since CNC, holdings should be updated.
	holdings, err := engine.store.GetHoldings(testEmail)
	require.NoError(t, err)
	assert.Len(t, holdings, 1)
}

func TestMonitor_FillSellOrder(t *testing.T) {
	prices := map[string]float64{"NSE:TCS": 3500.0}
	engine := testEngine(t, prices)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// First buy some shares.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	// Now place a SELL LIMIT at 3400 (below current 3500, so it fills).
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 3400.0,
	})
	require.NoError(t, err)

	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// The SELL order should be filled.
	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	// Both BUY (already filled) and SELL should be COMPLETE.
	completed := 0
	for _, o := range orders {
		if o.Status == "COMPLETE" {
			completed++
		}
	}
	assert.Equal(t, 2, completed)
}

func TestMonitor_InsufficientCashReject(t *testing.T) {
	prices := map[string]float64{"NSE:RELIANCE": 2500.0}
	engine := testEngine(t, prices)
	// Enable with very small cash.
	require.NoError(t, engine.Enable(testEmail, 100))

	// Place a BUY LIMIT that should be rejected by the monitor (cost > cash).
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 10, "price": 2600.0,
	})
	require.NoError(t, err)

	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// The order should be REJECTED due to insufficient cash.
	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "REJECTED", orders[0].Status)
}

func TestResetAccount(t *testing.T) {
	engine := testEngine(t, map[string]float64{"NSE:INFY": 1500.0})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place an order and fill it.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	// Reset.
	require.NoError(t, engine.store.ResetAccount(testEmail))

	// All cleared.
	orders, _ := engine.store.GetOrders(testEmail)
	assert.Empty(t, orders)
	positions, _ := engine.store.GetPositions(testEmail)
	assert.Empty(t, positions)
	holdings, _ := engine.store.GetHoldings(testEmail)
	assert.Empty(t, holdings)

	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_000_000.0, acct.CashBalance, 0.01)
}
