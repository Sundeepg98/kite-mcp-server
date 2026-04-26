package papertrading

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	engine := testEngine(t, nil)

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, false, status["enabled"])
	assert.Contains(t, status["message"], "not configured")
}

func TestStatus_Enabled(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	engine := testEngine(t, nil)

	_, err := engine.GetMargins(testEmail)
	require.Error(t, err, "should error for non-existent account")
	assert.Contains(t, err.Error(), "not enabled")
}

func TestGetMargins_Enabled(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	// Set initial LTP high so BUY LIMIT stays OPEN at placement.
	engine := testEngine(t, map[string]float64{"NSE:SBIN": 700.0})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place BUY LIMIT at 610. LTP is 700 so price(610) < ltp(700) → not
	// immediately marketable → order stays OPEN.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "CNC",
		"quantity":         100,
		"price":            610.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Now drop the mock LTP to 600 so the monitor will fill it
	// (shouldFill: ltp(600) <= price(610) → true).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 600.0}})

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

func TestMonitor_FillSellLimitOrder(t *testing.T) {
	t.Parallel()
	// Start with prices for BUY MARKET fill.
	prices := map[string]float64{"NSE:TCS": 3500.0}
	engine := testEngine(t, prices)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy some shares via MARKET order (fills immediately at 3500).
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	// Place SELL LIMIT at 3600 (above LTP 3500, so NOT immediately marketable).
	// This stays OPEN.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 3600.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Now change mock prices so LTP rises to 3700 (>= SELL limit 3600).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:TCS": 3700.0}})

	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// The SELL order should now be COMPLETE.
	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	completed := 0
	for _, o := range orders {
		if o.Status == "COMPLETE" {
			completed++
		}
	}
	assert.Equal(t, 2, completed, "both BUY and SELL should be COMPLETE")
}

func TestMonitor_InsufficientCashReject(t *testing.T) {
	t.Parallel()
	// Set LTP high initially so the BUY LIMIT at 2600 stays OPEN
	// (price 2600 < ltp 3000 → not marketable).
	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 3000.0})
	// Enable with very small cash (100). PlaceOrder LIMIT checks cost:
	// quantity(10) * price(2600) = 26000 > 100 → REJECTED at placement.
	// So use enough cash for the LIMIT check to pass but not enough for
	// monitor fill. Actually, the PlaceOrder LIMIT cash check uses the
	// limit price: 10 * 2600 = 26000. With cash=100 that rejects at placement.
	// We need cash >= 26000 for it to become OPEN, then drain cash before monitor.
	require.NoError(t, engine.Enable(testEmail, 30_000))

	// Place BUY LIMIT at 2600 (below LTP 3000 → stays OPEN).
	// Cash check: 10 * 2600 = 26000 < 30000 → passes.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 10, "price": 2600.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Now drain cash so the monitor fill check fails.
	require.NoError(t, engine.store.UpdateCashBalance(testEmail, 100))

	// Drop LTP so monitor triggers the fill: ltp(2500) <= price(2600).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2500.0}})

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
	t.Parallel()
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

// TestPlaceOrder_DispatchesDomainEvents pins the paper-engine -> domain event
// wiring activated in STEP 17. A MARKET BUY fill must emit OrderPlaced,
// OrderFilled, and PositionOpened events on the shared dispatcher so paper
// trades surface in /dashboard/activity, the event-sourcing projection, and
// the domain_events audit table alongside live trades.
func TestPlaceOrder_DispatchesDomainEvents(t *testing.T) {
	t.Parallel()
	engine := testEngine(t, map[string]float64{
		"NSE:RELIANCE": 2500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	dispatcher := domain.NewEventDispatcher()
	var (
		gotPlaced []domain.OrderPlacedEvent
		gotFilled []domain.OrderFilledEvent
		gotOpened []domain.PositionOpenedEvent
	)
	dispatcher.Subscribe("order.placed", func(e domain.Event) {
		gotPlaced = append(gotPlaced, e.(domain.OrderPlacedEvent))
	})
	dispatcher.Subscribe("order.filled", func(e domain.Event) {
		gotFilled = append(gotFilled, e.(domain.OrderFilledEvent))
	})
	dispatcher.Subscribe("position.opened", func(e domain.Event) {
		gotOpened = append(gotOpened, e.(domain.PositionOpenedEvent))
	})
	engine.SetDispatcher(dispatcher)

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)
	require.Equal(t, "COMPLETE", result["status"])

	require.Len(t, gotPlaced, 1, "expected 1 OrderPlacedEvent")
	require.Len(t, gotFilled, 1, "expected 1 OrderFilledEvent")
	require.Len(t, gotOpened, 1, "expected 1 PositionOpenedEvent")

	// All three events must be linked by the same paper order ID so
	// downstream consumers (projection, audit log) can correlate them.
	orderID := result["order_id"].(string)
	assert.Equal(t, orderID, gotPlaced[0].OrderID)
	assert.Equal(t, orderID, gotFilled[0].OrderID)
	assert.Equal(t, orderID, gotOpened[0].PositionID)

	assert.Equal(t, testEmail, gotPlaced[0].Email)
	assert.Equal(t, "BUY", gotPlaced[0].TransactionType)
	assert.Equal(t, 10, gotPlaced[0].Qty.Int())
	assert.InDelta(t, 2500.0, gotPlaced[0].Price.Amount, 0.01)

	assert.Equal(t, 10, gotFilled[0].FilledQty.Int())
	assert.InDelta(t, 2500.0, gotFilled[0].FilledPrice.Amount, 0.01)

	assert.Equal(t, "BUY", gotOpened[0].TransactionType)
	assert.Equal(t, "NSE", gotOpened[0].Instrument.Exchange)
	assert.Equal(t, "RELIANCE", gotOpened[0].Instrument.Tradingsymbol)
}

// --- ES: PaperOrderRejectedEvent dispatch ---
//
// Symmetric to OrderRejectedEvent on the live order path: paper-trading
// rejections (LTP unavailable for MARKET, insufficient cash on LIMIT
// BUY at place time, insufficient cash at fill time) must surface
// distinctly to the audit stream so projector consumers can render the
// virtual-account rejection timeline without parsing OrderID prefixes.

// TestPlaceOrder_MarketLTPUnavailable_DispatchesPaperRejected covers
// the MARKET path: when no LTP is available, PaperEngine rejects at
// place time with Status=REJECTED. Source must be "place_market" so
// projector consumers can distinguish this from cash-shortage paths.
func TestPlaceOrder_MarketLTPUnavailable_DispatchesPaperRejected(t *testing.T) {
	t.Parallel()
	// Empty LTP map -> fetchLTP returns "not found" error.
	engine := testEngine(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.PaperOrderRejectedEvent
	dispatcher.Subscribe("paper.order_rejected", func(e domain.Event) {
		captured = append(captured, e.(domain.PaperOrderRejectedEvent))
	})
	engine.SetDispatcher(dispatcher)

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

	require.Len(t, captured, 1, "PaperOrderRejectedEvent must fire on LTP-unavailable rejection")
	assert.Equal(t, testEmail, captured[0].Email)
	assert.Equal(t, "place_market", captured[0].Source)
	assert.Contains(t, captured[0].Reason, "LTP")
	assert.NotEmpty(t, captured[0].OrderID, "OrderID assigned before rejection branch")
	assert.False(t, captured[0].Timestamp.IsZero())
}

// TestPlaceOrder_LimitInsufficientCash_DispatchesPaperRejected covers
// the LIMIT BUY pre-place cash check: when the BUY notional exceeds
// cash balance, the order rejects before becoming OPEN. Source must
// be "place_limit" so the projector can distinguish this from the
// fill-time cash check ("fill_monitor").
func TestPlaceOrder_LimitInsufficientCash_DispatchesPaperRejected(t *testing.T) {
	t.Parallel()
	// LTP high so LIMIT 100 stays non-marketable for BUY.
	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 2500.0})
	require.NoError(t, engine.Enable(testEmail, 100)) // tiny cash

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.PaperOrderRejectedEvent
	dispatcher.Subscribe("paper.order_rejected", func(e domain.Event) {
		captured = append(captured, e.(domain.PaperOrderRejectedEvent))
	})
	engine.SetDispatcher(dispatcher)

	// Quantity 10 * limit 100 = 1000 > cash 100 → REJECTED at place.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         10,
		"price":            100.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])

	require.Len(t, captured, 1, "PaperOrderRejectedEvent must fire on LIMIT cash rejection")
	assert.Equal(t, testEmail, captured[0].Email)
	assert.Equal(t, "place_limit", captured[0].Source)
	assert.Contains(t, captured[0].Reason, "insufficient cash")
}

// TestPlaceOrder_FillImmediateInsufficientCash_DispatchesPaperRejected
// covers the fillOrder cash check: when a marketable LIMIT or MARKET
// order reaches fillOrder but cash dropped below the snap-to-LTP cost
// (e.g. between LIMIT acceptance and matching), the order rejects
// inside fillOrder. Source must be "fill_immediate".
func TestPlaceOrder_FillImmediateInsufficientCash_DispatchesPaperRejected(t *testing.T) {
	t.Parallel()
	// Marketable LIMIT BUY: price 2500 >= LTP 2500 → flows to fillOrder.
	// Cash 100 < fill cost 25000 → REJECTED inside fillOrder.
	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 2500.0})
	// Cash needs to clear the place-time check (price=0 marketable LIMIT
	// route uses fillOrder, but BUY LIMIT pre-check uses limit price).
	// Simpler: use MARKET BUY with cash-drain trick post-Enable to land
	// in fillOrder rejection branch deterministically.
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	require.NoError(t, engine.store.UpdateCashBalance(testEmail, 100))

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.PaperOrderRejectedEvent
	dispatcher.Subscribe("paper.order_rejected", func(e domain.Event) {
		captured = append(captured, e.(domain.PaperOrderRejectedEvent))
	})
	engine.SetDispatcher(dispatcher)

	// MARKET BUY → fillOrder → cost 25000 > cash 100 → REJECTED.
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

	require.Len(t, captured, 1, "PaperOrderRejectedEvent must fire on fillOrder cash rejection")
	assert.Equal(t, "fill_immediate", captured[0].Source)
	assert.Contains(t, captured[0].Reason, "insufficient cash")
}

// TestMonitor_InsufficientCashReject_DispatchesPaperRejected covers
// the background monitor path: when a queued LIMIT becomes marketable
// but cash dropped below the fill cost between place and fill, the
// monitor rejects the order. Source must be "fill_monitor" so projector
// consumers can identify the time-delayed rejection branch (place
// passed, fill failed) for forensic timeline reconstruction.
func TestMonitor_InsufficientCashReject_DispatchesPaperRejected(t *testing.T) {
	t.Parallel()
	// Mirror TestMonitor_InsufficientCashReject: place LIMIT at 2600
	// below LTP 3000 (stays OPEN), drain cash, flip LTP to 2500 to
	// trigger monitor fill, monitor rejects on cash check.
	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 3000.0})
	require.NoError(t, engine.Enable(testEmail, 30_000))

	dispatcher := domain.NewEventDispatcher()
	var captured []domain.PaperOrderRejectedEvent
	dispatcher.Subscribe("paper.order_rejected", func(e domain.Event) {
		captured = append(captured, e.(domain.PaperOrderRejectedEvent))
	})
	engine.SetDispatcher(dispatcher)

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 10, "price": 2600.0,
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", result["status"])

	require.NoError(t, engine.store.UpdateCashBalance(testEmail, 100))
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2500.0}})

	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "REJECTED", orders[0].Status)

	require.Len(t, captured, 1, "PaperOrderRejectedEvent must fire on monitor cash rejection")
	assert.Equal(t, "fill_monitor", captured[0].Source)
	assert.Equal(t, orders[0].OrderID, captured[0].OrderID,
		"monitor rejection event must carry the original paper order ID")
}

// TestPlaceOrder_NoDispatcher_RejectionPath_Safe verifies the nil-
// dispatcher fast path on rejection: a paper rejection without a
// wired dispatcher must not panic on a nil Dispatch call.
func TestPlaceOrder_NoDispatcher_RejectionPath_Safe(t *testing.T) {
	t.Parallel()
	engine := testEngine(t, map[string]float64{}) // No LTP -> rejects.
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	// Deliberately no SetDispatcher.

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         5,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])
}

// TestPlaceOrder_NoDispatcher_Safe verifies the nil-dispatcher fast path:
// paper trading must continue working identically for callers (tests, CLI)
// that never wire a dispatcher.
func TestPlaceOrder_NoDispatcher_Safe(t *testing.T) {
	t.Parallel()
	engine := testEngine(t, map[string]float64{
		"NSE:INFY": 1500.0,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	// Deliberately no SetDispatcher call.

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         5,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])
}
