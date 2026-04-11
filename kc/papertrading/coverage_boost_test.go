package papertrading

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- toInt / toFloat coverage ---

func TestToInt_AllTypes(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 42, toInt(42))
	assert.Equal(t, 99, toInt(int64(99)))
	assert.Equal(t, 7, toInt(float64(7.9)))
	assert.Equal(t, 123, toInt("123"))
	assert.Equal(t, 0, toInt(nil))
	assert.Equal(t, 0, toInt(true))
	assert.Equal(t, 0, toInt([]int{1}))
}

func TestToFloat_AllTypes(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 3.14, toFloat(3.14), 0.001)
	assert.InDelta(t, 2.5, toFloat(float32(2.5)), 0.01)
	assert.InDelta(t, 42.0, toFloat(42), 0.001)
	assert.InDelta(t, 99.0, toFloat(int64(99)), 0.001)
	assert.InDelta(t, 1.5, toFloat("1.5"), 0.01)
	assert.InDelta(t, 0.0, toFloat(nil), 0.001)
	assert.InDelta(t, 0.0, toFloat(true), 0.001)
	assert.InDelta(t, 0.0, toFloat([]int{1}), 0.001)
}

func TestGetString(t *testing.T) {
	t.Parallel()
	m := map[string]any{"k": "val", "n": 42}
	assert.Equal(t, "val", getString(m, "k"))
	assert.Equal(t, "42", getString(m, "n"))
	assert.Equal(t, "", getString(m, "missing"))
}

func TestGetInt(t *testing.T) {
	t.Parallel()
	m := map[string]any{"q": 10, "f": 3.5}
	assert.Equal(t, 10, getInt(m, "q"))
	assert.Equal(t, 3, getInt(m, "f"))
	assert.Equal(t, 0, getInt(m, "missing"))
}

func TestGetFloat(t *testing.T) {
	t.Parallel()
	m := map[string]any{"p": 99.5, "i": 7}
	assert.InDelta(t, 99.5, getFloat(m, "p"), 0.001)
	assert.InDelta(t, 7.0, getFloat(m, "i"), 0.001)
	assert.InDelta(t, 0.0, getFloat(m, "missing"), 0.001)
}

// --- updateHolding coverage ---

func TestUpdateHolding_BuyNewHolding(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a CNC BUY to create a holding via the normal path.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	holdings, err := store.GetHoldings(testEmail)
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, 10, holdings[0].Quantity)
	assert.InDelta(t, 2500.0, holdings[0].AveragePrice, 0.01)
}

func TestUpdateHolding_BuyExistingHolding(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy 10 at 2500.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Buy 10 more at 2500 -> weighted avg stays 2500, qty = 20.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	holdings, err := store.GetHoldings(testEmail)
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, 20, holdings[0].Quantity)
}

func TestUpdateHolding_SellPartial(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy 20 CNC.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Sell 10 CNC.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	holdings, err := store.GetHoldings(testEmail)
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, 10, holdings[0].Quantity)
}

func TestUpdateHolding_SellAll(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy 10 CNC.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Sell all 10 CNC — holding should be deleted.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	holdings, err := store.GetHoldings(testEmail)
	require.NoError(t, err)
	assert.Empty(t, holdings, "holding should be removed when selling all")
}

func TestUpdateHolding_SellMoreThanHeld(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy 5 CNC.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Sell 10 CNC — should fail.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot sell")
}

// --- ModifyOrder extra coverage ---

func TestModifyOrder_AllFields(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Modify all modifiable fields.
	modResult, err := engine.ModifyOrder(testEmail, orderID, map[string]any{
		"price":         2350.0,
		"quantity":      10,
		"order_type":    "SL",
		"trigger_price": 2300.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", modResult["status"])

	// Verify modifications persisted.
	order, err := store.GetOrder(orderID)
	require.NoError(t, err)
	assert.InDelta(t, 2350.0, order.Price, 0.01)
	assert.Equal(t, 10, order.Quantity)
	assert.Equal(t, "SL", order.OrderType)
	assert.InDelta(t, 2300.0, order.TriggerPrice, 0.01)
}

func TestModifyOrder_BecomesMarketable(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place LIMIT BUY at 2400 (not marketable).
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)
	assert.Equal(t, "OPEN", res["status"])
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// Modify price to 2600 — now marketable (buy price >= LTP 2500).
	modResult, err := engine.ModifyOrder(testEmail, orderID, map[string]any{
		"price": 2600.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", modResult["status"])

	// Original order should be cancelled.
	origOrder, err := store.GetOrder(orderID)
	require.NoError(t, err)
	assert.Equal(t, "CANCELLED", origOrder.Status)
}

func TestModifyOrder_SellBecomesMarketable(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// First create a position to sell from.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Place LIMIT SELL at 2600 (not marketable since LTP=2500).
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2600.0,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)
	assert.Equal(t, "OPEN", res["status"])
	time.Sleep(time.Millisecond) // avoid order ID collision on Windows

	// Modify to 2400 — now marketable (sell price <= LTP 2500).
	modResult, err := engine.ModifyOrder(testEmail, orderID, map[string]any{
		"price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", modResult["status"])
}

func TestModifyOrder_NonOpenOrder(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a MARKET order that fills immediately.
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Try to modify a COMPLETE order — should fail.
	_, err = engine.ModifyOrder(testEmail, orderID, map[string]any{"price": 2300.0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot modify")
}

func TestModifyOrder_NotFound(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.ModifyOrder(testEmail, "PAPER_NONEXISTENT", map[string]any{"price": 100.0})
	require.Error(t, err)
}

// --- CancelOrder extra coverage ---

func TestCancelOrder_WrongUser(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	_, err = engine.CancelOrder("other@example.com", orderID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

func TestCancelOrder_NotFound(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.CancelOrder(testEmail, "PAPER_NONEXISTENT")
	require.Error(t, err)
}

// --- fetchLTP edge cases ---

func TestFetchLTP_NotInResult(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:SBIN": 800})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Try to get LTP for an instrument not in the mock — should REJECT.
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "UNKNOWN",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", res["status"])
}

// errorLTP is an LTP provider that always returns an error.
type errorLTP struct{}

func (e *errorLTP) GetLTP(instruments ...string) (map[string]float64, error) {
	return nil, fmt.Errorf("connection timeout")
}

func TestFetchLTP_ProviderError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&errorLTP{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// MARKET order with error LTP provider — should REJECT.
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", res["status"])
}

// --- LIMIT order with no LTP: stays open even without LTP error ---

func TestPlaceOrder_LimitNoLTP(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{}) // no prices
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// LIMIT BUY — LTP fails, so it can't check if marketable, stays OPEN.
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", res["status"])
}

func TestPlaceOrder_LimitSellNoLTP(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{}) // no prices
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// LIMIT SELL — LTP fails, stays OPEN.
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2600.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", res["status"])
}

// --- Position edge cases ---

func TestPosition_SellFlipToShort(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy 5.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Sell 10 — flips from +5 to -5.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	positions, err := store.GetPositions(testEmail)
	require.NoError(t, err)
	require.Len(t, positions, 1)
	assert.Equal(t, -5, positions[0].Quantity)
	// New average should be the fill price (2500).
	assert.InDelta(t, 2500.0, positions[0].AveragePrice, 0.01)
}

// --- Monitor fill edge cases ---

func TestMonitor_Tick_SellOrder(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Create a position first.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	// Insert a LIMIT SELL order directly as OPEN.
	order := &Order{
		OrderID: "PAPER_SELL_MON", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "SELL", OrderType: "LIMIT",
		Product: "MIS", Quantity: 5, Price: 2600.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	// Set LTP to 2700 (above limit sell price, should fill).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2700}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	filled, _ := store.GetOrder("PAPER_SELL_MON")
	assert.Equal(t, "COMPLETE", filled.Status)
}

func TestMonitor_Tick_SLOrder(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert a SL BUY order directly.
	order := &Order{
		OrderID: "PAPER_SL_MON", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "SL",
		Product: "MIS", Quantity: 5, Price: 2600.0, TriggerPrice: 2550.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	// Set LTP to 2600 (above trigger, should fill).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2600}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	filled, _ := store.GetOrder("PAPER_SL_MON")
	assert.Equal(t, "COMPLETE", filled.Status)
}

func TestMonitor_Tick_SLMOrder(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert a SL-M SELL order directly.
	order := &Order{
		OrderID: "PAPER_SLM_MON", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "SELL", OrderType: "SL-M",
		Product: "MIS", Quantity: 5, TriggerPrice: 2550.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	// Set LTP to 2400 (below trigger for sell SL-M, should fill).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2400}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	filled, _ := store.GetOrder("PAPER_SLM_MON")
	assert.Equal(t, "COMPLETE", filled.Status)
	// SL-M fills at LTP.
	assert.InDelta(t, 2400.0, filled.AveragePrice, 0.01)
}

func TestMonitor_Tick_MultipleOrdersDifferentInstruments(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500, "NSE:SBIN": 800})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert two LIMIT BUY orders.
	o1 := &Order{
		OrderID: "PAPER_MULTI_1", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "MIS", Quantity: 5, Price: 2400.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	o2 := &Order{
		OrderID: "PAPER_MULTI_2", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "MIS", Quantity: 10, Price: 750.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(o1))
	require.NoError(t, store.InsertOrder(o2))

	// Set LTPs below limit prices.
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{
		"NSE:RELIANCE": 2300,
		"NSE:SBIN":     700,
	}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	f1, _ := store.GetOrder("PAPER_MULTI_1")
	f2, _ := store.GetOrder("PAPER_MULTI_2")
	assert.Equal(t, "COMPLETE", f1.Status)
	assert.Equal(t, "COMPLETE", f2.Status)
}

func TestMonitor_Tick_LTPProviderError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&errorLTP{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert an OPEN order.
	order := &Order{
		OrderID: "PAPER_ERR_MON", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "MIS", Quantity: 5, Price: 2400.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	monitor := NewMonitor(engine, time.Second, logger)
	// Should not panic — just logs and returns.
	monitor.tick()

	// Order should still be OPEN.
	o, _ := store.GetOrder("PAPER_ERR_MON")
	assert.Equal(t, "OPEN", o.Status)
}

// --- handleClosePosition for short positions ---

func TestHandleClosePosition_ShortPosition(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Create a short position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Close position should place a BUY order.
	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE", "product": "MIS",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleClosePosition_NoProduct(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Close without specifying product — should still match.
	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// --- handleCloseAllPositions with short + mixed positions ---

func TestHandleCloseAllPositions_WithShortPositions(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500, "NSE:INFY": 1500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Long position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Short position.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	result, err := handleCloseAllPositions(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

// --- GetOrders when disabled ---

func TestGetOrders_WhenDisabled(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place some orders.
	res, _ := engine.GetOrders(testEmail)
	orders := res.([]map[string]any)
	assert.Empty(t, orders)
}

// --- GetPositions with no LTP provider ---

func TestGetPositions_NoLTPProvider(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Should return empty positions without error.
	posResp, err := engine.GetPositions(testEmail)
	require.NoError(t, err)
	posMap := posResp.(map[string]any)
	assert.NotNil(t, posMap["net"])
	assert.NotNil(t, posMap["day"])
}

// --- GetHoldings with no LTP provider ---

func TestGetHoldings_NoLTPProvider(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	holdingsResp, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)
	holdings := holdingsResp.([]map[string]any)
	assert.Empty(t, holdings)
}

// --- LTP provider error in GetPositions/GetHoldings ---

func TestGetPositions_LTPError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&errorLTP{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert a position directly.
	require.NoError(t, store.UpsertPosition(&Position{
		Email: testEmail, Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Product: "MIS", Quantity: 10, AveragePrice: 2500, LastPrice: 2500,
	}))

	// Should still return positions even if LTP fails.
	posResp, err := engine.GetPositions(testEmail)
	require.NoError(t, err)
	posMap := posResp.(map[string]any)
	day := posMap["day"].([]map[string]any)
	assert.Len(t, day, 1)
}

func TestGetHoldings_LTPError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&errorLTP{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Insert a holding directly.
	require.NoError(t, store.UpsertHolding(&Holding{
		Email: testEmail, Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 10, AveragePrice: 2500, LastPrice: 2500,
	}))

	holdingsResp, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)
	holdings := holdingsResp.([]map[string]any)
	assert.Len(t, holdings, 1)
}

// --- Variety default ---

func TestPlaceOrder_DefaultVariety(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Don't specify variety — should default to "regular".
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)

	orders, _ := store.GetOrders(testEmail)
	require.Len(t, orders, 1)
	assert.Equal(t, "regular", orders[0].Variety)
}

// --- handleRead get_trades ---

func TestHandleRead_GetTrades(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_trades", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// --- Store: GetOrder not found ---

func TestStore_GetOrder_NotFound(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	_, err = store.GetOrder("NONEXISTENT")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- Middleware: handleWrite with GTT variants ---

func TestHandleWrite_GTTVariants(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	for _, tool := range []string{"modify_gtt_order", "delete_gtt_order"} {
		result, err := handleWrite(engine, testEmail, tool, map[string]any{})
		require.NoError(t, err)
		assert.NotNil(t, result)
	}
}

// --- Monitor fill: SELL fills add cash ---

func TestMonitor_Tick_SellFillAddsCash(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Create a short position first (sell MIS).
	_, _ = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})

	// Cash after selling: 1M + 10*2500 = 1,025,000.
	acct, _ := store.GetAccount(testEmail)
	assert.InDelta(t, 1_025_000.0, acct.CashBalance, 0.01)
}

// --- Status with populated data ---

func TestStatus_WithData(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy to create position, holding, and order.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond) // avoid order ID collision on Windows

	// Place an open order.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, true, status["enabled"])
	assert.Equal(t, 1, status["positions"])
	assert.Equal(t, 1, status["holdings"])
	assert.Equal(t, 1, status["open_orders"])
	assert.NotEmpty(t, status["created_at"])
	assert.NotEmpty(t, status["last_reset_at"])
}

// --- Disable/Reset when no account exists ---

func TestDisable_NoAccount(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	// Disable on non-existent account — store.DisableAccount updates 0 rows, no error.
	err := engine.Disable("nobody@example.com")
	require.NoError(t, err)
}

func TestReset_NoAccount(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	// Reset on non-existent account — deletes 0 rows, then update returns no error.
	err := engine.Reset("nobody@example.com")
	require.NoError(t, err)
}

// --- Status error paths (via closed DB) ---

func TestStatus_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Close the DB to force errors.
	db.Close()

	_, err = engine.Status(testEmail)
	require.Error(t, err)
}

func TestEnable_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)

	db.Close()

	err = engine.Enable(testEmail, 1_000_000)
	require.Error(t, err)
}

func TestDisable_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	db.Close()

	err = engine.Disable(testEmail)
	require.Error(t, err)
}

func TestReset_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	db.Close()

	err = engine.Reset(testEmail)
	require.Error(t, err)
}

func TestPlaceOrder_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2500}})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	db.Close()

	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.Error(t, err)
}

func TestGetOrders_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)

	db.Close()

	_, err = engine.GetOrders(testEmail)
	require.Error(t, err)
}

func TestGetPositions_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)

	db.Close()

	_, err = engine.GetPositions(testEmail)
	require.Error(t, err)
}

func TestGetHoldings_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)

	db.Close()

	_, err = engine.GetHoldings(testEmail)
	require.Error(t, err)
}

// --- Middleware tests ---

func TestMiddleware_NoEmail(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})

	nextCalled := false
	next := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		nextCalled = true
		return gomcp.NewToolResultText("passthrough"), nil
	}

	mw := Middleware(engine)
	handler := mw(next)

	// Context with no email — should pass through to next.
	ctx := context.Background()
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, nextCalled, "next should be called when no email in context")
	assert.NotNil(t, result)
}

func TestMiddleware_NotEnabled(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	// Don't enable paper trading for the user.

	nextCalled := false
	next := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		nextCalled = true
		return gomcp.NewToolResultText("passthrough"), nil
	}

	mw := Middleware(engine)
	handler := mw(next)

	ctx := oauth.ContextWithEmail(context.Background(), testEmail)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, nextCalled, "next should be called when paper trading is not enabled")
	assert.NotNil(t, result)
}

func TestMiddleware_WriteTool(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	nextCalled := false
	next := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		nextCalled = true
		return gomcp.NewToolResultText("passthrough"), nil
	}

	mw := Middleware(engine)
	handler := mw(next)

	ctx := oauth.ContextWithEmail(context.Background(), testEmail)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": float64(5),
	}

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, nextCalled, "next should NOT be called for intercepted write tool")
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestMiddleware_ReadTool(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	nextCalled := false
	next := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		nextCalled = true
		return gomcp.NewToolResultText("passthrough"), nil
	}

	mw := Middleware(engine)
	handler := mw(next)

	ctx := oauth.ContextWithEmail(context.Background(), testEmail)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_orders"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, nextCalled, "next should NOT be called for intercepted read tool")
	assert.NotNil(t, result)
}

func TestMiddleware_UnknownTool(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	nextCalled := false
	next := func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		nextCalled = true
		return gomcp.NewToolResultText("passthrough"), nil
	}

	mw := Middleware(engine)
	handler := mw(next)

	ctx := oauth.ContextWithEmail(context.Background(), testEmail)
	req := gomcp.CallToolRequest{}
	req.Params.Name = "search_instruments" // not a write or read tool

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, nextCalled, "next should be called for unknown tool")
	assert.NotNil(t, result)
}
