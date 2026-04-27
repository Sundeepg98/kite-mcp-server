package papertrading

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- toInt / toFloat coverage ---


// --- ModifyOrder extra coverage ---
func TestModifyOrder_AllFields(t *testing.T) {
	t.Parallel()
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
	assert.InDelta(t, 2350.0, order.Price.Float64(), 0.01)
	assert.Equal(t, 10, order.Quantity)
	assert.Equal(t, "SL", order.OrderType)
	assert.InDelta(t, 2300.0, order.TriggerPrice, 0.01)
}


func TestModifyOrder_BecomesMarketable(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// First create a position to sell from.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	// Place LIMIT SELL at 2600 (not marketable since LTP=2500).
	res, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2600.0,
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)
	assert.Equal(t, "OPEN", res["status"])

	// Modify to 2400 — now marketable (sell price <= LTP 2500).
	modResult, err := engine.ModifyOrder(testEmail, orderID, map[string]any{
		"price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", modResult["status"])
}


func TestModifyOrder_NonOpenOrder(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.ModifyOrder(testEmail, "PAPER_NONEXISTENT", map[string]any{"price": 100.0})
	require.Error(t, err)
}


// --- CancelOrder extra coverage ---
func TestCancelOrder_WrongUser(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.CancelOrder(testEmail, "PAPER_NONEXISTENT")
	require.Error(t, err)
}


// ---------------------------------------------------------------------------
// ModifyOrder: GetAccount error during modify+fill (line 462-464)
// ---------------------------------------------------------------------------
func TestModifyOrder_GetAccountError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Place a LIMIT BUY at 400 (not marketable at LTP 500)
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Drop accounts table entirely so GetAccount fails. Disable FK enforcement
	// for the DROP because paper_orders.email REFERENCES paper_accounts(email)
	// ON DELETE CASCADE — without this, the orphaned paper_orders row would be
	// cascade-deleted (modernc.org/sqlite cascades on DROP), defeating the
	// test's purpose of failing GetAccount specifically.
	require.NoError(t, db.ExecInsert("PRAGMA foreign_keys=OFF"))
	err = db.ExecInsert("DROP TABLE paper_accounts")
	require.NoError(t, err)
	require.NoError(t, db.ExecInsert("PRAGMA foreign_keys=ON"))

	// Modify price to 600 (>= LTP 500 → marketable → triggers fillOrder → needs GetAccount)
	_, err = engine.ModifyOrder(gapEmail, orderID, map[string]any{
		"price": float64(600),
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get account for fill")
}


// COVERAGE NOTE: ModifyOrder line 466-468 (UpdateOrderStatus error during
// modify+fill) requires GetOrder and GetAccount to succeed but UpdateOrderStatus
// to fail, which is not feasible without DB-level mocking in a single call.

// ---------------------------------------------------------------------------
// ModifyOrder: ExecInsert error in update (line 479-481)
// ---------------------------------------------------------------------------
func TestModifyOrder_UpdateError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	// Place an OPEN order (LIMIT BUY at 400, LTP 500 → not marketable)
	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	// Close DB so the UPDATE in ModifyOrder fails
	db.Close()

	// ModifyOrder: changes price to 350 (still not marketable) → tries UPDATE → fails
	_, err = engine.ModifyOrder(gapEmail, orderID, map[string]any{
		"price": float64(350),
	})
	assert.Error(t, err)
}


// ---------------------------------------------------------------------------
// CancelOrder: UpdateOrderStatus error (line 498-500)
// ---------------------------------------------------------------------------
func TestCancelOrder_UpdateError(t *testing.T) {
	t.Parallel()
	engine, db := gapEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(gapEmail, 1_000_000))

	res, err := engine.PlaceOrder(gapEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "BUY",
		"order_type": "LIMIT", "product": "CNC", "quantity": 5, "price": float64(400),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	db.Close()

	_, err = engine.CancelOrder(gapEmail, orderID)
	assert.Error(t, err)
}


func TestModifyOrder_MarketableAfterModify_BUY(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

	// Place LIMIT SELL at 600 (above LTP 500 → not marketable → OPEN)
	res, err := engine.PlaceOrder(pushEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "transaction_type": "SELL",
		"order_type": "LIMIT", "product": "CNC", "quantity": 10, "price": float64(600),
	})
	require.NoError(t, err)
	orderID := res["order_id"].(string)

	order, _ := engine.store.GetOrder(orderID)
	assert.Equal(t, "OPEN", order.Status)


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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
// ModifyOrder — change order_type and trigger_price
// ---------------------------------------------------------------------------
func TestModifyOrder_ChangeOrderType(t *testing.T) {
	t.Parallel()
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
