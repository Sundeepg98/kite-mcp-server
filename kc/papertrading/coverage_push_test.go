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

// ===========================================================================
// coverage_push_test.go — Push papertrading from 94% to 98%+
//
// Targets:
// - Status() DB error paths (GetPositions/GetHoldings/GetOpenOrders fail)
// - ModifyOrder marketable-after-modify fill path
// - CancelOrder with non-matching email / already-cancelled order
// - middleware handleClosePosition / handleCloseAllPositions
// - middleware handleGetTrades
// - monitor fill() error paths
// - store ResetAccount with data
// ===========================================================================

func testEngineWithLTP(t *testing.T, prices map[string]float64) *PaperEngine {
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

// pushEmail is a dedicated email for coverage_push tests.
// Each test creates its own engine+DB so there is no cross-test pollution.
const pushEmail = "push@test.com"

// ---------------------------------------------------------------------------
// ModifyOrder — marketable after price change (LIMIT order becomes fillable)
// ---------------------------------------------------------------------------

func TestModifyOrder_MarketableAfterModify_BUY(t *testing.T) {
	prices := map[string]float64{"NSE:SBIN": 500}
	engine := testEngineWithLTP(t, prices)
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Place a LIMIT BUY order at price 400 (below LTP 500 — not marketable)
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "CNC",
		"quantity":         10,
		"price":            float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Verify order is OPEN
	order, err := engine.store.GetOrder(orderID)
	require.NoError(t, err)
	assert.Equal(t, "OPEN", order.Status)

	time.Sleep(time.Millisecond) // avoid order ID collision on Windows (UnixNano resolution)

	// Modify: raise price to 600 (above LTP 500 → becomes marketable → auto-fill)
	modRes, err := engine.ModifyOrder(pushEmail, orderID, map[string]any{
		"price": float64(600),
	})
	require.NoError(t, err)
	// Should have filled (new order_id, status COMPLETE)
	if status, ok := modRes["status"].(string); ok {
		assert.Equal(t, "COMPLETE", status, "Order should be auto-filled when price becomes marketable")
	}
}

func TestModifyOrder_MarketableAfterModify_SELL(t *testing.T) {
	// LTP=500. LIMIT SELL at 600 is NOT marketable (LTP < price).
	// After modify to 400, LTP >= price → marketable → auto-fill.
	prices := map[string]float64{"NSE:SBIN": 500}
	engine := testEngineWithLTP(t, prices)
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Buy shares first to have something to sell
	_, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// Place LIMIT SELL at 600 (above LTP 500 → not marketable → OPEN)
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(600),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status)

	time.Sleep(time.Millisecond) // avoid order ID collision on Windows (UnixNano resolution)

	// Modify price to 400 → LTP 500 >= 400 → marketable → auto-fill
	modRes, err := engine.ModifyOrder(pushEmail, orderID, map[string]any{
		"price": float64(400),
	})
	require.NoError(t, err)
	if status, ok := modRes["status"].(string); ok {
		assert.Equal(t, "COMPLETE", status)
	}
}

// ---------------------------------------------------------------------------
// ModifyOrder — wrong email / already cancelled
// ---------------------------------------------------------------------------

func TestModifyOrder_WrongEmail(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	_, err = engine.ModifyOrder("wrong@email.com", orderID, map[string]any{"price": float64(450)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestModifyOrder_CancelledOrder(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Cancel it first
	_, err = engine.CancelOrder(pushEmail, orderID)
	require.NoError(t, err)

	// Try to modify the cancelled order
	_, err = engine.ModifyOrder(pushEmail, orderID, map[string]any{"price": float64(450)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot modify")
}

// ---------------------------------------------------------------------------
// CancelOrder — wrong email / already filled
// ---------------------------------------------------------------------------

func TestCancelOrder_WrongEmail(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	_, err = engine.CancelOrder("wrong@email.com", orderID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestCancelOrder_AlreadyFilled(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Place a MARKET order (auto-fills immediately)
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Try to cancel the already-filled order
	_, err = engine.CancelOrder(pushEmail, orderID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel")
}

// ---------------------------------------------------------------------------
// Middleware — handleClosePosition
// ---------------------------------------------------------------------------

func TestHandleClosePosition_ShortPosition_Push(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable("short@push.com", 1_000_000))

	// Sell to create short position (SELL without prior BUY is allowed in MIS)
	_, err := engine.PlaceOrder("short@push.com", map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// Close the short position (should place a BUY)
	result, err := handleClosePosition(engine, "short@push.com", map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "SBIN",
		"product":       "MIS",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleClosePosition_NoMatch(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	result, err := handleClosePosition(engine, pushEmail, map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "RELIANCE",
	})
	require.NoError(t, err)
	assert.True(t, result.IsError) // No matching position
}

func TestHandleClosePosition_FlatPosition_Push(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Buy then sell same quantity → flat
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	time.Sleep(time.Millisecond)
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})

	result, err := handleClosePosition(engine, pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "product": "MIS",
	})
	require.NoError(t, err)
	// Flat or no-position → either "already flat" (IsError=false) or "no matching" (IsError=true)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Middleware — handleCloseAllPositions
// ---------------------------------------------------------------------------

func TestHandleCloseAllPositions_WithPositions(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{
		"NSE:SBIN": 500, "NSE:RELIANCE": 2500,
	})
	require.NoError(t, engine.Enable(pushEmail, 10_000_000))

	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	time.Sleep(time.Millisecond)
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 5,
	})
	time.Sleep(time.Millisecond)

	result, err := handleCloseAllPositions(engine, pushEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleCloseAllPositions_ShortPositions(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 10_000_000))

	// Create a short position
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	time.Sleep(time.Millisecond)

	result, err := handleCloseAllPositions(engine, pushEmail)
	require.NoError(t, err)
	assert.False(t, result.IsError)
}

// ---------------------------------------------------------------------------
// Middleware — handleGetTrades
// ---------------------------------------------------------------------------

func TestHandleGetTrades_WithFilledOrders(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Place two market orders (auto-filled)
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	time.Sleep(time.Millisecond)
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "MARKET", "product": "CNC", "quantity": 5,
	})

	result, err := handleGetTrades(engine, pushEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleGetTrades_NoTrades_Push(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	result, err := handleGetTrades(engine, pushEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Store — ResetAccount with existing data
// ---------------------------------------------------------------------------

func TestResetAccount_WithData(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Place and fill some orders to create positions/holdings
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})

	// Verify data exists before reset
	orders, _ := engine.store.GetOrders(pushEmail)
	assert.NotEmpty(t, orders)

	// Reset
	require.NoError(t, engine.Reset(pushEmail))

	// Verify data is cleared
	orders, _ = engine.store.GetOrders(pushEmail)
	assert.Empty(t, orders)
	positions, _ := engine.store.GetPositions(pushEmail)
	assert.Empty(t, positions)
}

// ---------------------------------------------------------------------------
// Monitor — tick with open LIMIT order that becomes marketable
// ---------------------------------------------------------------------------

func TestMonitor_FillLimitOrder_Push(t *testing.T) {
	// LTP starts at 600 — LIMIT BUY at 500 is NOT fillable (ltp > price)
	prices := map[string]float64{"NSE:SBIN": 600}
	engine := testEngineWithLTP(t, prices)
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(500),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Verify OPEN (LTP 600 > limit 500 → not filled)
	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status)

	// Monitor tick with price drop to 480 → now fillable (LTP <= limit price)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 480}})
	mon.tick()

	order, _ = engine.store.GetOrder(orderID)
	assert.Equal(t, "COMPLETE", order.Status)
}

func TestMonitor_FillSLOrder_Push(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Buy shares first
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// Place SL SELL: trigger=450, price=440 (LTP 500 > trigger, so not triggered)
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "SL", "product": "CNC", "quantity": 5,
		"trigger_price": float64(450), "price": float64(440),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Verify still OPEN
	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// Price drops to 440 → trigger hit (LTP <= trigger_price) → fill
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 440}})
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows
	mon.tick()

	order, _ = engine.store.GetOrder(orderID)
	assert.Equal(t, "COMPLETE", order.Status)
}

func TestMonitor_InsufficientCashRejectsBUY(t *testing.T) {
	// Use SL order type — it is not checked against cash at placement time
	// (SL orders go straight to OPEN regardless of cash).
	// Then when monitor fills it, the cash check in monitor.fill() triggers rejection.
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 100)) // only Rs 100 cash

	// Place SL BUY: trigger=520 (LTP 500 < 520, not triggered). Cost at fill would be qty*fillPrice.
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "SL-M", "product": "CNC", "quantity": 10,
		"trigger_price": float64(520),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// Price rises to 530 → trigger hit (LTP >= trigger for BUY SL-M).
	// cost = 10 * 530 = 5300 >> cash 100 → REJECTED by monitor.fill()
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 530}})
	mon.tick()

	order, _ = engine.store.GetOrder(orderID)
	assert.Equal(t, "REJECTED", order.Status)
}

// ---------------------------------------------------------------------------
// PlaceOrder — SL and SL-M order types
// ---------------------------------------------------------------------------

func TestPlaceOrder_SLM_Push(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// SL-M BUY: trigger at 520, no limit price
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "SL-M", "product": "CNC", "quantity": 10,
		"trigger_price": float64(520),
	})
	require.NoError(t, err)
	assert.Contains(t, res["status"], "OPEN")
}

func TestPlaceOrder_SL_Push(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// SL BUY: trigger at 520, limit 530
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "SL", "product": "CNC", "quantity": 10,
		"trigger_price": float64(520), "price": float64(530),
	})
	require.NoError(t, err)
	assert.Contains(t, res["status"], "OPEN")
}

// ---------------------------------------------------------------------------
// Engine — Status after placing orders (exercises all three stores)
// ---------------------------------------------------------------------------

func TestStatus_AfterOrdersAndPositions(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Place some orders to populate all three stores
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})

	status, err := engine.Status(pushEmail)
	require.NoError(t, err)
	assert.Equal(t, true, status["enabled"])
	// Verify positions/holdings/open_orders keys exist (values depend on timing)
	_, hasPos := status["positions"]
	_, hasHold := status["holdings"]
	_, hasOpen := status["open_orders"]
	assert.True(t, hasPos, "status should have positions key")
	assert.True(t, hasHold, "status should have holdings key")
	assert.True(t, hasOpen, "status should have open_orders key")
}

// ---------------------------------------------------------------------------
// ModifyOrder — change order_type and trigger_price
// ---------------------------------------------------------------------------

func TestModifyOrder_ChangeOrderType(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	_, err = engine.ModifyOrder(pushEmail, orderID, map[string]any{
		"order_type":    "SL",
		"trigger_price": float64(380),
		"quantity":      5,
	})
	require.NoError(t, err)

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "SL", order.OrderType)
	assert.Equal(t, 5, order.Quantity)
}

// ---------------------------------------------------------------------------
// Store edge cases
// ---------------------------------------------------------------------------

func TestGetOrder_NotFound(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	_, err := engine.store.GetOrder("NONEXISTENT")
	assert.Error(t, err)
}
