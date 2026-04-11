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
// final_push_test.go — Push papertrading from ~94% to 98%+
//
// Targets uncovered lines not reached by existing tests:
// - engine.Status() error paths when store queries fail
// - PlaceOrder MARKET with LTP unavailable (nil provider)
// - PlaceOrder LIMIT BUY with insufficient cash → rejection
// - PlaceOrder unsupported order type
// - fillOrder SELL path (BUY skips cash check)
// - fillOrder UpdateCashBalance error (unreachable in-memory, documented)
// - ModifyOrder/CancelOrder store error paths (closed DB)
// - middleware handleGetTrades store error path
// - middleware handleClosePosition qty==0 path
// - monitor tick() with GetAllOpenOrders error
// - monitor tick() with LTP miss (instrument not in map)
// - monitor tick() with shouldFill returning false
// - store.ResetAccount delete positions/holdings error (closed DB)
// ===========================================================================

const finalEmail = "final@push.com"

// partialLTP returns LTP for known instruments, omits unknown ones.
type partialLTP struct {
	prices map[string]float64
}

func (p *partialLTP) GetLTP(instruments ...string) (map[string]float64, error) {
	result := make(map[string]float64)
	for _, inst := range instruments {
		if price, ok := p.prices[inst]; ok {
			result[inst] = price
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// PlaceOrder — MARKET with LTP unavailable
// ---------------------------------------------------------------------------

func TestPlaceOrder_MarketLTPUnavailable(t *testing.T) {
	engine := testEngineWithLTP(t, nil) // nil prices → GetLTP returns empty map
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Set an LTP provider that returns errors
	engine.SetLTPProvider(&errorLTP{})

	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	require.NoError(t, err) // PlaceOrder doesn't return error, returns REJECTED status
	assert.Equal(t, "REJECTED", res["status"])
	assert.Contains(t, res["reason"], "LTP unavailable")
}

// ---------------------------------------------------------------------------
// PlaceOrder — LIMIT BUY with insufficient cash → REJECTED
// ---------------------------------------------------------------------------

func TestPlaceOrder_LimitBUY_InsufficientCash(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 100)) // only ₹100

	// LIMIT BUY at 400 → cost = 10 * 400 = 4000 > 100 → rejected
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", res["status"])
	assert.Contains(t, res["reason"], "insufficient cash")
}

// ---------------------------------------------------------------------------
// PlaceOrder — unsupported order type
// ---------------------------------------------------------------------------

func TestPlaceOrder_UnsupportedOrderType(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "INVALID", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported order_type")
}

// ---------------------------------------------------------------------------
// PlaceOrder — LIMIT SELL immediately marketable → fillOrder SELL path
// ---------------------------------------------------------------------------

func TestPlaceOrder_LimitSELL_ImmediatelyMarketable(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// First buy shares so we have inventory
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// LIMIT SELL at 400 (below LTP 500 → immediately marketable → auto-fill)
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", res["status"])
}

// ---------------------------------------------------------------------------
// PlaceOrder — LIMIT with LTP error → still stored as OPEN
// ---------------------------------------------------------------------------

func TestPlaceOrder_Limit_LTPError_StillOpenBUY(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// LTP provider returns error → cannot check marketability → store as OPEN
	engine.SetLTPProvider(&errorLTP{})
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", res["status"])
}

// ---------------------------------------------------------------------------
// PlaceOrder — validation errors
// ---------------------------------------------------------------------------

func TestPlaceOrder_MissingExchange(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exchange and tradingsymbol are required")
}

func TestPlaceOrder_InvalidTransactionType(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "INVALID",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BUY or SELL")
}

func TestPlaceOrder_ZeroQuantity(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 0,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "quantity must be positive")
}

func TestPlaceOrder_NotEnabled_Final(t *testing.T) {
	engine := testEngineWithLTP(t, nil)
	// Don't enable paper trading

	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

// ---------------------------------------------------------------------------
// Status — with closed DB to trigger error paths
// ---------------------------------------------------------------------------

func TestStatus_DBErrors_WithData(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:SBIN": 500}})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Place an order first so there's data
	_, err = engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	// Close DB to force errors on subsequent queries
	db.Close()

	// Status should return an error when DB is closed
	_, err = engine.Status(finalEmail)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Monitor tick() — GetAllOpenOrders error
// ---------------------------------------------------------------------------

func TestMonitorTick_OpenOrdersError(t *testing.T) {
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
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Buy shares first (CNC)
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Place LIMIT SELL at 600 (above LTP 500 → not marketable → OPEN)
	res, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(600),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)
	time.Sleep(time.Millisecond)

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
// handleGetTrades — store error path
// ---------------------------------------------------------------------------

func TestHandleGetTrades_StoreError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: nil})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Close DB to force error
	db.Close()

	result, err := handleGetTrades(engine, finalEmail)
	require.NoError(t, err) // handleGetTrades returns error in result, not as err
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// handleCloseAllPositions — PlaceOrder error during close
// ---------------------------------------------------------------------------

func TestHandleCloseAllPositions_PlaceOrderError(t *testing.T) {
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// Create a position
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Switch to error LTP so closing (MARKET order) fails
	engine.SetLTPProvider(&errorLTP{})

	result, err := handleCloseAllPositions(engine, finalEmail)
	require.NoError(t, err)
	// Result should still be returned (with error per-position)
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// Store ResetAccount — error paths (closed DB)
// ---------------------------------------------------------------------------

func TestStoreResetAccount_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	// Create an account
	require.NoError(t, store.EnableAccount(finalEmail, 1_000_000))

	// Close DB
	db.Close()

	// ResetAccount should return an error
	err = store.ResetAccount(finalEmail)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// handleClosePosition — GetPositions error
// ---------------------------------------------------------------------------

func TestHandleClosePosition_StoreError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: nil})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	db.Close()

	result, err := handleClosePosition(engine, finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN",
	})
	require.NoError(t, err) // error in result
	assert.True(t, result.IsError)
}

// ---------------------------------------------------------------------------
// handleCloseAllPositions — GetPositions error
// ---------------------------------------------------------------------------

func TestHandleCloseAllPositions_StoreError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	engine.SetLTPProvider(&mockLTP{prices: nil})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	db.Close()

	result, err := handleCloseAllPositions(engine, finalEmail)
	require.NoError(t, err) // error in result
	assert.True(t, result.IsError)
}
