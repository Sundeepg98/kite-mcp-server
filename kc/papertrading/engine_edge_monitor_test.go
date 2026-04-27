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

// --- toInt / toFloat coverage ---


// --- Monitor fill edge cases ---
func TestMonitor_Tick_SellOrder(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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


// --- Monitor fill: SELL fills add cash ---
func TestMonitor_Tick_SellFillAddsCash(t *testing.T) {
	t.Parallel()
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
	assert.InDelta(t, 1_025_000.0, acct.CashBalance.Float64(), 0.01)
}


func TestMonitorFill_InsufficientCash(t *testing.T) {
	t.Parallel()
	// LTP starts at 500. LIMIT BUY at 400 won't fill yet.
	engine := push100Engine(t, map[string]float64{"NSE:SBIN": 500, "NSE:RELIANCE": 2000})
	require.NoError(t, engine.Enable(push100Email, 10_000))

	// Place a LIMIT BUY: 10 shares at 400 → cost 4000 < 10000 → accepted as OPEN
	res, err := engine.PlaceOrder(push100Email, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"product":          "MIS",
		"quantity":         10,
		"price":            float64(400),
	})
	require.NoError(t, err)
	limitOrderID := res["order_id"].(string)
	assert.Equal(t, "OPEN", res["status"])

	// Drain cash: MARKET BUY 4 shares of RELIANCE at 2000 → cost 8000
	// Remaining cash: 10000 - 8000 = 2000 < 4000 (cost of the LIMIT order)
	_, err = engine.PlaceOrder(push100Email, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         4,
	})
	require.NoError(t, err)

	// Verify cash is now 2000
	acct, err := engine.store.GetAccount(push100Email)
	require.NoError(t, err)
	assert.InDelta(t, 2000, acct.CashBalance.Float64(), 1)

	// Now drop LTP to 400 so the LIMIT BUY triggers, but cash (2000) < cost (4000)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 400}})
	mon.tick()

	// The order should be REJECTED due to insufficient cash
	order, err := engine.store.GetOrder(limitOrderID)
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", order.Status)
}


// ---------------------------------------------------------------------------
// fillOrder: InsertOrder error on BUY REJECTED in fillOrder (line 233-235)
// ---------------------------------------------------------------------------
func TestFillOrder_InsertRejectedBUY(t *testing.T) {
	t.Parallel()
	// fillOrder BUY REJECTED path: cost > CashBalance → InsertOrder of rejected order
	// We need InsertOrder to fail, so drop orders table first.
	engine, db := gapEngine(t, map[string]float64{"NSE:EXPENSIVE": 50000})
	require.NoError(t, engine.Enable(gapEmail, 100)) // cost = 50000*10 = 500000 > 100

	err := db.ExecInsert("DROP TABLE paper_orders")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "EXPENSIVE", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert rejected order")
}


// ---------------------------------------------------------------------------
// Monitor fill(): BUY rejected (insufficient cash, line 159)
// ---------------------------------------------------------------------------
func TestMonitorFill_BUYRejected(t *testing.T) {
	t.Parallel()
	engine, _ := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1000)) // very low cash

	// Place a LIMIT BUY at 400 (LTP=500 > 400, so ltp<=price is false → not marketable → OPEN)
	// Cash check passes for LIMIT BUY: cost = 5 * 400 = 2000 > 1000 → REJECTED at PlaceOrder
	// So we need to pick a price where the LIMIT check passes at PlaceOrder time.
	// PlaceOrder LIMIT BUY insufficient cash: cost = qty * price > cashBalance → REJECTED.
	// So let's use qty=1, price=400 → cost 400 < 1000 → OPEN.
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 1, "price": float64(400),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])

	// Now drop LTP to 300 (< 400 → shouldFill true for LIMIT BUY)
	// fill price = 400 (limit price). Cost = 1 * 400 = 400 < 1000 → would fill.
	// We need cost > cash. Use a much larger qty. But we already placed with qty=1.
	// Alternative: drain cash first by placing another order.
	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 1,
	})
	require.NoError(t, err)
	// After market buy at 500: cash = 1000 - 500 = 500

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 1,
	})
	require.NoError(t, err)
	// After 2nd market buy at 500: cash = 500 - 500 = 0

	// Now LIMIT BUY at 400 with qty=1, cash=0 → cost 400 > 0 → REJECTED
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 300}})

	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick()

	order, err := engine.store.GetOrder(res["order_id"].(string))
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", order.Status)
}


// ---------------------------------------------------------------------------
// Monitor fill(): UpdateOrderStatus error (line 169-172)
// ---------------------------------------------------------------------------
func TestMonitorFill_UpdateOrderStatusError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Place a SELL LIMIT at 600 (LTP 500, not marketable). Need inventory first.
	_, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "MIS", "quantity": 5, "price": float64(600),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])

	// Now close DB so fill() → UpdateOrderStatus fails
	db.Close()
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 700}})

	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick() // should log error, not panic
}


// ---------------------------------------------------------------------------
// Monitor fill(): UpdateCashBalance error (line 180-183)
// ---------------------------------------------------------------------------
func TestMonitorFill_UpdateCashBalanceError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Place LIMIT BUY at 400
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])

	// Drop accounts table (but keep orders) so UpdateCashBalance fails.
	// Disable FK enforcement so paper_orders rows survive the DROP — without
	// this, ON DELETE CASCADE would purge them and the test would not
	// exercise the UpdateCashBalance failure path.
	require.NoError(t, db.ExecInsert("PRAGMA foreign_keys=OFF"))
	err = db.ExecInsert("DROP TABLE paper_accounts")
	require.NoError(t, err)
	// Create a minimal accounts table so GetAccount works but UpdateCashBalance fails
	err = db.ExecInsert("CREATE TABLE paper_accounts (email TEXT PRIMARY KEY)")
	require.NoError(t, err)
	db.ExecInsert("INSERT INTO paper_accounts (email) VALUES (?)", gapEmail)
	require.NoError(t, db.ExecInsert("PRAGMA foreign_keys=ON"))

	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 300}})

	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick() // cash update fails, logged
}


// ---------------------------------------------------------------------------
// Monitor fill(): updatePosition error (line 188-191)
// ---------------------------------------------------------------------------
func TestMonitorFill_UpdatePositionError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])

	// Drop positions table so updatePosition fails
	err = db.ExecInsert("DROP TABLE paper_positions")
	require.NoError(t, err)

	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 300}})
	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick()
}


// ---------------------------------------------------------------------------
// Monitor fill(): updateHolding error (line 195-198)
// ---------------------------------------------------------------------------
func TestMonitorFill_UpdateHoldingError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])

	// Drop holdings table so updateHolding fails (positions table stays)
	err = db.ExecInsert("DROP TABLE paper_holdings")
	require.NoError(t, err)

	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 300}})
	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick()
}


// ---------------------------------------------------------------------------
// Monitor fill(): SELL path in monitor (covers CNC holding update via monitor)
// ---------------------------------------------------------------------------
func TestMonitorFill_SELL_CNC(t *testing.T) {
	t.Parallel()
	engine, _ := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Buy CNC shares first
	_, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)

	// Place LIMIT SELL at 600 (not marketable, LTP=500)
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(600),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])
	orderID := res["order_id"].(string)

	// Raise LTP to trigger fill
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 700}})
	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick()

	order, err := engine.store.GetOrder(orderID)
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", order.Status)
}


// ---------------------------------------------------------------------------
// Monitor fill(): MIS product (no holding update, line 194 skipped)
// ---------------------------------------------------------------------------
func TestMonitorFill_MIS_NoHoldingUpdate(t *testing.T) {
	t.Parallel()
	engine, _ := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Place LIMIT BUY at 400, MIS product
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "MIS", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	require.Equal(t, "OPEN", res["status"])
	orderID := res["order_id"].(string)

	// Drop LTP so LIMIT BUY at 400 is fillable (LTP <= 400)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 350}})
	mon := NewMonitor(engine, 0, gapLogger())
	mon.tick()

	order, err := engine.store.GetOrder(orderID)
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", order.Status)

	// No holdings should exist (MIS product)
	holdings, err := engine.store.GetHoldings(gapEmail)
	require.NoError(t, err)
	assert.Empty(t, holdings)
}


// ---------------------------------------------------------------------------
// Monitor tick() — GetAllOpenOrders error
// ---------------------------------------------------------------------------
func TestMonitorTick_OpenOrdersError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 500}})

	mon := NewMonitor(engine, 0, logger)

	// Close DB to force error on GetAllOpenOrders
	db.Close()

	// tick should handle error gracefully (no panic)
	mon.tick()
}


// ---------------------------------------------------------------------------
// Monitor tick() — LTP miss for some instruments
// ---------------------------------------------------------------------------
func TestMonitorTick_LTPMiss(t *testing.T) {
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Place a LIMIT BUY for RELIANCE (not in our LTP map)
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(2000),
	})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// tick with LTP only for SBIN — RELIANCE should be skipped (LTP miss)
	engine.SetLTPProvider(&partialLTP{prices: map[string]float64{"NSE:SBIN": 500}})
	mon.tick()

	// Order should still be OPEN (not filled since no LTP)
	orders, _ := engine.store.GetOrders(finalEmail)
	for _, o := range orders {
		if o.Tradingsymbol == "RELIANCE" {
			assert.Equal(t, "OPEN", o.Status)
		}
	}
}


// ---------------------------------------------------------------------------
// Monitor tick() — shouldFill returns false (price not right)
// ---------------------------------------------------------------------------
func TestMonitorTick_ShouldFillFalse(t *testing.T) {
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// LIMIT BUY at 400 — LTP=500 > 400 → not fillable
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// tick with LTP still at 500 — shouldFill returns false
	mon.tick()

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status, "Order should remain OPEN")
}


// ---------------------------------------------------------------------------
// Monitor fill() — SELL path (exercises cash addition, no cash check)
// ---------------------------------------------------------------------------
func TestMonitorTick_FillSELL_CNC(t *testing.T) {
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Buy shares first (CNC)
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)

	// Place LIMIT SELL at 600 (above LTP 500 → not marketable → OPEN)
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(600),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// Price rises to 650 → SELL LIMIT fills (LTP >= price)
	// This exercises monitor.fill() SELL path + CNC holdings update
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 650}})
	mon.tick()

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "COMPLETE", order.Status)
}


// ---------------------------------------------------------------------------
// Monitor tick() — LTP error path
// ---------------------------------------------------------------------------
func TestMonitorTick_LTPError(t *testing.T) {
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Place an OPEN order
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mon := NewMonitor(engine, 0, logger)

	// Switch to error LTP provider
	engine.SetLTPProvider(&errorLTP{})
	mon.tick() // should handle error gracefully
}


// ---------------------------------------------------------------------------
// Monitor — tick with open LIMIT order that becomes marketable
// ---------------------------------------------------------------------------
func TestMonitor_FillLimitOrder_Push(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(pushEmail, 1_000_000))

	// Buy shares first
	_, _ = engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})

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
	mon.tick()

	order, _ = engine.store.GetOrder(orderID)
	assert.Equal(t, "COMPLETE", order.Status)
}


func TestMonitor_InsufficientCashRejectsBUY(t *testing.T) {
	t.Parallel()
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
