package papertrading

import (
	"log/slog"
	"os"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// --- toInt / toFloat coverage ---


// --- LIMIT order with no LTP: stays open even without LTP error ---
func TestPlaceOrder_LimitNoLTP(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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


// --- Variety default ---
func TestPlaceOrder_DefaultVariety(t *testing.T) {
	t.Parallel()
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


func TestPlaceOrder_DBError(t *testing.T) {
	t.Parallel()
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


// ---------------------------------------------------------------------------
// PlaceOrder MARKET: InsertOrder error on REJECTED path (line 173)
// ---------------------------------------------------------------------------
func TestPlaceOrder_Market_InsertRejectedError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, nil)
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))
	engine.SetLTPProvider(&errorLTP{})

	// Drop orders table to cause insert to fail
	err := db.ExecInsert("DROP TABLE paper_orders")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert rejected order")
}


// ---------------------------------------------------------------------------
// PlaceOrder LIMIT: InsertOrder error on REJECTED (insufficient cash) path (line 199-201)
// ---------------------------------------------------------------------------
func TestPlaceOrder_Limit_InsertRejectedError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 10)) // very low cash

	err := db.ExecInsert("DROP TABLE paper_orders")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert rejected order")
}


// ---------------------------------------------------------------------------
// PlaceOrder SL: InsertOrder error (line 214-216)
// ---------------------------------------------------------------------------
func TestPlaceOrder_SL_InsertError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	err := db.ExecInsert("DROP TABLE paper_orders")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "SL", "product": "CNC", "quantity": 10,
		"price": float64(400), "trigger_price": float64(410),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert SL order")
}


// COVERAGE NOTE: fillOrder line 257-259 (UpdateCashBalance error) is only
// triggerable by closing the DB between InsertOrder and UpdateCashBalance
// in a single synchronous call, which is not feasible without mocking.
// The same error path IS tested via Monitor.fill() in TestMonitorFill_UpdateCashBalanceError.

// ---------------------------------------------------------------------------
// updatePosition: GetPositions error (line 286-288)
// ---------------------------------------------------------------------------
func TestPlaceOrder_UpdatePositionError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Drop positions table after enabling
	err := db.ExecInsert("DROP TABLE paper_positions")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update position")
}


// ---------------------------------------------------------------------------
// updateHolding: GetHoldings error (line 370-372)
// ---------------------------------------------------------------------------
func TestPlaceOrder_UpdateHoldingError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Drop holdings table after enabling (positions table intact so updatePosition succeeds)
	err := db.ExecInsert("DROP TABLE paper_holdings")
	require.NoError(t, err)

	_, err = engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "update holding")
}


// ---------------------------------------------------------------------------
// PlaceOrder LIMIT with insert error on OPEN path (line 206-208)
// ---------------------------------------------------------------------------
func TestPlaceOrder_Limit_InsertOpenError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, nil)
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))
	engine.SetLTPProvider(&errorLTP{}) // LTP error → can't check marketability → go to OPEN path

	// Close the DB so InsertOrder fails (GetAccount already returned before this)
	db.Close()

	_, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(400),
	})
	assert.Error(t, err)
}


// ---------------------------------------------------------------------------
// Verify gomcp import is used (silence linter)
// ---------------------------------------------------------------------------
var _ gomcp.CallToolResult

const finalEmail = "final@push.com"

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
func TestPlaceOrder_MarketLTPUnavailable(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	engine := testEngineWithLTP(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(finalEmail, 1_000_000))

	// First buy shares so we have inventory
	_, err := engine.PlaceOrder(finalEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 20,
	})
	require.NoError(t, err)

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
// PlaceOrder — SL and SL-M order types
// ---------------------------------------------------------------------------
func TestPlaceOrder_SLM_Push(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
