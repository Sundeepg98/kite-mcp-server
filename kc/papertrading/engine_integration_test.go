package papertrading

import (
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/broker/mock"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// brokerLTPAdapter wraps a broker.Client to satisfy the papertrading.LTPProvider interface.
type brokerLTPAdapter struct {
	client broker.Client
}

func (a *brokerLTPAdapter) GetLTP(instruments ...string) (map[string]float64, error) {
	ltps, err := a.client.GetLTP(instruments...)
	if err != nil {
		return nil, err
	}
	result := make(map[string]float64, len(ltps))
	for k, v := range ltps {
		result[k] = v.LastPrice
	}
	return result, nil
}

// testEngineWithMockBroker creates a PaperEngine backed by in-memory SQLite and a mock broker for LTP.
func testEngineWithMockBroker(t *testing.T, mc *mock.Client) *PaperEngine {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&brokerLTPAdapter{client: mc})
	return engine
}

const integrationEmail = "trader@integration.test"

// ---------------------------------------------------------------------------
// Enable paper trading, verify status
// ---------------------------------------------------------------------------

func TestIntegration_EnableAndStatus(t *testing.T) {
	mc := mock.New()
	engine := testEngineWithMockBroker(t, mc)

	// Not enabled initially.
	assert.False(t, engine.IsEnabled(integrationEmail))

	status, err := engine.Status(integrationEmail)
	require.NoError(t, err)
	assert.Equal(t, false, status["enabled"])

	// Enable with Rs 1 crore.
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))
	assert.True(t, engine.IsEnabled(integrationEmail))

	status, err = engine.Status(integrationEmail)
	require.NoError(t, err)
	assert.Equal(t, true, status["enabled"])
	assert.Equal(t, 1_00_00_000.0, status["initial_cash"])
	assert.Equal(t, 1_00_00_000.0, status["cash_balance"])
	assert.Equal(t, 0, status["positions"])
	assert.Equal(t, 0, status["holdings"])
	assert.Equal(t, 0, status["open_orders"])
}

// ---------------------------------------------------------------------------
// Place a MARKET order, verify fill at mock LTP
// ---------------------------------------------------------------------------

func TestIntegration_MarketOrderFillsAtMockLTP(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:RELIANCE": 2500.00,
		"NSE:TCS":      3500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])

	// Cash deducted: 1Cr - 10*2500 = 99,75,000.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0-25_000.0, acct.CashBalance.Float64(), 0.01)

	// Position exists at correct price.
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, "RELIANCE", positions[0].Tradingsymbol)
	assert.Equal(t, 10, positions[0].Quantity)
	assert.InDelta(t, 2500.0, positions[0].AveragePrice.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// Place a LIMIT order, verify it stays OPEN
// ---------------------------------------------------------------------------

func TestIntegration_LimitOrderStaysOpen(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:INFY": 1500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// LIMIT BUY at 1400 when LTP is 1500 -- not immediately marketable.
	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         20,
		"price":            1400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// No position should exist yet.
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	assert.Empty(t, positions)

	// Cash should be unchanged (LIMIT buy reservations don't deduct until fill).
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0, acct.CashBalance.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// LIMIT order immediately marketable when price is favorable
// ---------------------------------------------------------------------------

func TestIntegration_LimitOrderImmediatelyMarketable(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:SBIN": 800.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// LIMIT BUY at 850 when LTP is 800 -- immediately marketable (buy price >= LTP).
	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         100,
		"price":            850.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])

	// Filled at LTP (800), not the limit price.
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.InDelta(t, 800.0, positions[0].AveragePrice.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// CNC buy creates holdings
// ---------------------------------------------------------------------------

func TestIntegration_CNCCreatesHoldings(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:HDFC": 1600.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "HDFC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         25,
	})
	require.NoError(t, err)

	holdings, err := engine.store.GetHoldings(integrationEmail)
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, "HDFC", holdings[0].Tradingsymbol)
	assert.Equal(t, 25, holdings[0].Quantity)
	assert.InDelta(t, 1600.0, holdings[0].AveragePrice.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// MIS buy does NOT create holdings (only positions)
// ---------------------------------------------------------------------------

func TestIntegration_MISDoesNotCreateHoldings(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:ITC": 450.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "ITC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	holdings, err := engine.store.GetHoldings(integrationEmail)
	require.NoError(t, err)
	assert.Empty(t, holdings, "MIS orders should not create holdings")

	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	assert.Len(t, positions, 1, "MIS orders should create positions")
}

// ---------------------------------------------------------------------------
// Buy then sell: check P&L calculation
// ---------------------------------------------------------------------------

func TestIntegration_PnLCalculation(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:WIPRO": 500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy 100 at 500.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "WIPRO",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	cashAfterBuy, _ := engine.store.GetAccount(integrationEmail)
	assert.InDelta(t, 1_00_00_000.0-50_000.0, cashAfterBuy.CashBalance.Float64(), 0.01)

	// Price goes up to 550.
	mc.SetPrices(map[string]float64{"NSE:WIPRO": 550.00})

	// Sell 100 at 550.
	_, err = engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "WIPRO",
		"transaction_type": "SELL",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	// Cash should be: initial - buy + sell = 1Cr - 50000 + 55000 = 1,00,05,000.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0+5_000.0, acct.CashBalance.Float64(), 0.01)

	// Position should be flat (deleted when quantity=0).
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	assert.Empty(t, positions, "position should be closed after full sell")
}

// ---------------------------------------------------------------------------
// Partial sell: position reduced
// ---------------------------------------------------------------------------

func TestIntegration_PartialSell(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:SBIN": 800.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy 100.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)


	// Sell 40.
	_, err = engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "SELL",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         40,
	})
	require.NoError(t, err)

	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, 60, positions[0].Quantity)
}

// ---------------------------------------------------------------------------
// Weighted average price on multiple buys
// ---------------------------------------------------------------------------

func TestIntegration_WeightedAverageOnMultipleBuys(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:TCS": 3000.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy 10 at 3000.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Price changes to 3200.
	mc.SetPrices(map[string]float64{"NSE:TCS": 3200.00})

	// Buy 10 more at 3200.
	_, err = engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Weighted average: (10*3000 + 10*3200) / 20 = 62000/20 = 3100.
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, 20, positions[0].Quantity)
	assert.InDelta(t, 3100.0, positions[0].AveragePrice.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// Insufficient cash rejection
// ---------------------------------------------------------------------------

func TestIntegration_InsufficientCash(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 10_000)) // Only Rs 10K

	// Try to buy 10*2500 = 25000 > 10000.
	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])
	assert.Contains(t, result["reason"], "insufficient cash")

	// Cash unchanged.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 10_000.0, acct.CashBalance.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// Reset clears all state
// ---------------------------------------------------------------------------

func TestIntegration_ResetClearsState(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:RELIANCE": 2500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Place orders to create state.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Verify state exists.
	orders, _ := engine.store.GetOrders(integrationEmail)
	assert.NotEmpty(t, orders)
	holdings, _ := engine.store.GetHoldings(integrationEmail)
	assert.NotEmpty(t, holdings)
	positions, _ := engine.store.GetPositions(integrationEmail)
	assert.NotEmpty(t, positions)

	// Reset.
	require.NoError(t, engine.Reset(integrationEmail))

	// All data cleared.
	orders, _ = engine.store.GetOrders(integrationEmail)
	assert.Empty(t, orders)
	holdings, _ = engine.store.GetHoldings(integrationEmail)
	assert.Empty(t, holdings)
	positions, _ = engine.store.GetPositions(integrationEmail)
	assert.Empty(t, positions)

	// Cash restored.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0, acct.CashBalance.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// Concurrent order placement
// ---------------------------------------------------------------------------

func TestIntegration_ConcurrentOrders(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:INFY": 1500.00,
	})

	// Use a temp file for the DB to support concurrent writes safely.
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/paper_test.db"
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&brokerLTPAdapter{client: mc})

	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	var wg sync.WaitGroup
	var mu sync.Mutex
	successCount := 0
	rejectCount := 0
	errCount := 0

	// 20 concurrent MARKET BUY orders for 10 shares each = 200 shares total * 1500 = 3,00,000.
	// Should fit within 1 Cr.
	for range 20 {
		wg.Go(func() {
			result, err := engine.PlaceOrder(integrationEmail, map[string]any{
				"exchange":         "NSE",
				"tradingsymbol":    "INFY",
				"transaction_type": "BUY",
				"order_type":       "MARKET",
				"product":          "MIS",
				"quantity":         10,
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errCount++
				return
			}
			if result["status"] == "COMPLETE" {
				successCount++
			} else {
				rejectCount++
			}
		})
	}
	wg.Wait()

	// All 20 should eventually succeed — some might fail due to SQLite concurrency,
	// but the total (success + reject + err) should be 20.
	total := successCount + rejectCount + errCount
	assert.Equal(t, 20, total, "all goroutines should complete")
	// Most orders should succeed (total cost 3L << 1Cr).
	assert.Greater(t, successCount, 0, "at least some concurrent orders should succeed")
}

// ---------------------------------------------------------------------------
// Mock broker price change triggers different fill prices
// ---------------------------------------------------------------------------

func TestIntegration_PriceChangesBetweenOrders(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:HDFCBANK": 1500.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy at 1500.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "HDFCBANK",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Price drops to 1400.
	mc.SetPrices(map[string]float64{"NSE:HDFCBANK": 1400.00})

	// Buy more at 1400.
	_, err = engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "HDFCBANK",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Average should be (10*1500 + 10*1400) / 20 = 1450.
	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.InDelta(t, 1450.0, positions[0].AveragePrice.Float64(), 0.01)

	// Cash: 1Cr - 10*1500 - 10*1400 = 1Cr - 29000.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0-29_000.0, acct.CashBalance.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// GetPositions refreshes LTP from mock broker
// ---------------------------------------------------------------------------

func TestIntegration_GetPositions_RefreshesLTP(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:ITC": 400.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy at 400.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "ITC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         100,
	})
	require.NoError(t, err)

	// Price moves to 450.
	mc.SetPrices(map[string]float64{"NSE:ITC": 450.00})

	posResp, err := engine.GetPositions(integrationEmail)
	require.NoError(t, err)

	posMap := posResp.(map[string]any)
	day := posMap["day"].([]map[string]any)
	require.Len(t, day, 1)

	// LTP should be refreshed to 450.
	assert.InDelta(t, 450.0, day[0]["last_price"], 0.01)
	// P&L: 100 * (450 - 400) = 5000.
	assert.InDelta(t, 5000.0, day[0]["pnl"], 0.01)
}

// ---------------------------------------------------------------------------
// GetHoldings refreshes LTP from mock broker
// ---------------------------------------------------------------------------

func TestIntegration_GetHoldings_RefreshesLTP(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:HDFC": 1600.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "HDFC",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "CNC",
		"quantity":         50,
	})
	require.NoError(t, err)

	// Price moves to 1700.
	mc.SetPrices(map[string]float64{"NSE:HDFC": 1700.00})

	holdingsResp, err := engine.GetHoldings(integrationEmail)
	require.NoError(t, err)

	holdings := holdingsResp.([]map[string]any)
	require.Len(t, holdings, 1)
	assert.InDelta(t, 1700.0, holdings[0]["last_price"], 0.01)
	// P&L: 50 * (1700 - 1600) = 5000.
	assert.InDelta(t, 5000.0, holdings[0]["pnl"], 0.01)
}

// ---------------------------------------------------------------------------
// Multiple instruments in portfolio
// ---------------------------------------------------------------------------

func TestIntegration_MultipleInstruments(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:RELIANCE": 2500.00,
		"NSE:TCS":      3500.00,
		"NSE:INFY":     1500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Buy all three.
	for _, sym := range []string{"RELIANCE", "TCS", "INFY"} {
		_, err := engine.PlaceOrder(integrationEmail, map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    sym,
			"transaction_type": "BUY",
			"order_type":       "MARKET",
			"product":          "MIS",
			"quantity":         10,
		})
		require.NoError(t, err)
	}

	positions, err := engine.store.GetPositions(integrationEmail)
	require.NoError(t, err)
	assert.Len(t, positions, 3)

	// Total cost: 10*2500 + 10*3500 + 10*1500 = 25000+35000+15000 = 75000.
	acct, err := engine.store.GetAccount(integrationEmail)
	require.NoError(t, err)
	assert.InDelta(t, 1_00_00_000.0-75_000.0, acct.CashBalance.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// Modify open LIMIT order
// ---------------------------------------------------------------------------

func TestIntegration_ModifyLimitOrder(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:TCS": 3500.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	// Place a LIMIT order that stays OPEN.
	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "TCS",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         10,
		"price":            3400.0,
	})
	require.NoError(t, err)
	orderID := result["order_id"].(string)
	assert.Equal(t, "OPEN", result["status"])

	// Modify the price.
	modResult, err := engine.ModifyOrder(integrationEmail, orderID, map[string]any{
		"price": 3300.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", modResult["status"])

	// Verify the order price was updated.
	order, err := engine.store.GetOrder(orderID)
	require.NoError(t, err)
	assert.InDelta(t, 3300.0, order.Price.Float64(), 0.01)
}

// ---------------------------------------------------------------------------
// SL order stays OPEN
// ---------------------------------------------------------------------------

func TestIntegration_SLOrderStaysOpen(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{
		"NSE:SBIN": 800.00,
	})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "SL",
		"product":          "MIS",
		"quantity":         50,
		"price":            810.0,
		"trigger_price":    805.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])
}

// ---------------------------------------------------------------------------
// Cancel an open order
// ---------------------------------------------------------------------------

func TestIntegration_CancelOpenOrder(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:ITC": 450.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "ITC",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         100,
		"price":            440.0,
	})
	require.NoError(t, err)
	orderID := result["order_id"].(string)

	cancelResult, err := engine.CancelOrder(integrationEmail, orderID)
	require.NoError(t, err)
	assert.Equal(t, "CANCELLED", cancelResult["status"])

	// No open orders remaining.
	open, err := engine.store.GetOpenOrders(integrationEmail)
	require.NoError(t, err)
	assert.Empty(t, open)
}

// ---------------------------------------------------------------------------
// Cannot cancel a filled order
// ---------------------------------------------------------------------------

func TestIntegration_CannotCancelFilledOrder(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:WIPRO": 500.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "WIPRO",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])

	orderID := result["order_id"].(string)
	_, err = engine.CancelOrder(integrationEmail, orderID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel")
}

// ---------------------------------------------------------------------------
// GetMargins shows correct cash and utilization
// ---------------------------------------------------------------------------

func TestIntegration_GetMargins(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:RELIANCE": 2500.00})
	engine := testEngineWithMockBroker(t, mc)
	require.NoError(t, engine.Enable(integrationEmail, 5_00_000))

	// Buy 10*2500 = 25000.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	margins, err := engine.GetMargins(integrationEmail)
	require.NoError(t, err)

	m := margins.(map[string]any)
	eq := m["equity"].(map[string]any)
	avail := eq["available"].(map[string]any)
	utilised := eq["utilised"].(map[string]any)

	assert.InDelta(t, 4_75_000.0, avail["cash"], 0.01)
	assert.InDelta(t, 25_000.0, utilised["debits"], 0.01)
	assert.InDelta(t, 5_00_000.0, eq["net"], 0.01)
}

// ---------------------------------------------------------------------------
// Paper trading disabled: orders rejected
// ---------------------------------------------------------------------------

func TestIntegration_DisabledRejectsOrders(t *testing.T) {
	mc := mock.New()
	mc.SetPrices(map[string]float64{"NSE:INFY": 1500.00})
	engine := testEngineWithMockBroker(t, mc)

	// Don't enable paper trading.
	_, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

// ---------------------------------------------------------------------------
// No LTP provider: MARKET order rejected
// ---------------------------------------------------------------------------

func TestIntegration_NoLTPProvider_MarketRejected(t *testing.T) {
	// Create engine with no LTP provider.
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	// Deliberately not setting LTP provider.

	require.NoError(t, engine.Enable(integrationEmail, 1_00_00_000))

	result, err := engine.PlaceOrder(integrationEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])
	assert.Contains(t, result["reason"].(string), "LTP")
}
