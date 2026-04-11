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

// testEngineWithStore is like testEngine but also returns the store.
func testEngineWithStore(t *testing.T, prices map[string]float64) (*PaperEngine, *Store) {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	if prices != nil {
		engine.SetLTPProvider(&mockLTP{prices: prices})
	}
	return engine, store
}

// --- GetOrders ---

func TestGetOrders(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	result, err := engine.GetOrders(testEmail)
	require.NoError(t, err)
	orders, ok := result.([]map[string]any)
	require.True(t, ok)
	assert.Len(t, orders, 1)
	assert.Equal(t, "COMPLETE", orders[0]["status"])
}

// --- orderToMap ---

func TestOrderToMap(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	order := &Order{
		OrderID: "PAPER_123", Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "MARKET", Product: "CNC",
		Variety: "regular", Quantity: 10, Status: "COMPLETE",
		FilledQuantity: 10, AveragePrice: 2500.0,
		PlacedAt: now, FilledAt: now, Tag: "test",
	}
	m := orderToMap(order)
	assert.Equal(t, "PAPER_123", m["order_id"])
	assert.Equal(t, "COMPLETE", m["status"])
	assert.Equal(t, 10, m["filled_quantity"])
	assert.NotNil(t, m["filled_at"])
}

func TestOrderToMap_NoFill(t *testing.T) {
	t.Parallel()
	order := &Order{OrderID: "PAPER_456", Status: "OPEN", PlacedAt: time.Now().UTC()}
	m := orderToMap(order)
	assert.Equal(t, "OPEN", m["status"])
	_, hasFilled := m["filled_at"]
	assert.False(t, hasFilled, "filled_at should not be present for unfilled orders")
}

// --- shouldFill ---

func TestShouldFill_Limit(t *testing.T) {
	t.Parallel()
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: 2500}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: 2500}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: 2500}, 2600))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: 2500}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: 2500}, 2600))
	assert.False(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: 2500}, 2400))
}

func TestShouldFill_SL(t *testing.T) {
	t.Parallel()
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: 2500}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: 2500}, 2600))
	assert.False(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: 2500}, 2400))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: 2500}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: 2500}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: 2500}, 2600))
}

func TestShouldFill_SLM(t *testing.T) {
	t.Parallel()
	assert.True(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "BUY", TriggerPrice: 2500}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "SELL", TriggerPrice: 2500}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "BUY", TriggerPrice: 2500}, 2400))
}

func TestShouldFill_UnknownType(t *testing.T) {
	t.Parallel()
	assert.False(t, shouldFill(&Order{OrderType: "FOK", TransactionType: "BUY"}, 2500))
}

// --- determineFillPrice ---

func TestDetermineFillPrice(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 2400.0, determineFillPrice(&Order{OrderType: "LIMIT", Price: 2400}, 2500))
	assert.Equal(t, 2600.0, determineFillPrice(&Order{OrderType: "SL", Price: 2600}, 2500))
	assert.Equal(t, 2500.0, determineFillPrice(&Order{OrderType: "SL", Price: 0}, 2500))
	assert.Equal(t, 2500.0, determineFillPrice(&Order{OrderType: "SL-M"}, 2500))
	assert.Equal(t, 2500.0, determineFillPrice(&Order{OrderType: "FOK"}, 2500))
}

// --- Monitor ---

func TestMonitor_Tick(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place a LIMIT BUY at 2400 (below LTP 2500), stays OPEN.
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Change LTP to 2300 (below limit price, should fill).
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2300}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	orders, err := store.GetOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "COMPLETE", orders[0].Status)
}

func TestMonitor_Tick_NoOpenOrders(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick() // Should not panic.
}

func TestMonitor_StartStop(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, 50*time.Millisecond, logger)
	monitor.Start()
	time.Sleep(100 * time.Millisecond)
	monitor.Stop()
}

func TestMonitor_Tick_InsufficientCash(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 100)) // very small cash

	// Insert LIMIT order directly.
	order := &Order{
		OrderID: "PAPER_CASH_TEST", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "MIS", Quantity: 10, Price: 2400.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2300}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	orders, _ := store.GetOrders(testEmail)
	require.Len(t, orders, 1)
	assert.Equal(t, "REJECTED", orders[0].Status)
}

func TestMonitor_Tick_CNCUpdatesHoldings(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	order := &Order{
		OrderID: "PAPER_CNC_MON", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "CNC", Quantity: 5, Price: 2400.0,
		Status: "OPEN", PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))

	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:RELIANCE": 2300}})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, time.Second, logger)
	monitor.tick()

	holdings, _ := store.GetHoldings(testEmail)
	require.Len(t, holdings, 1)
	assert.Equal(t, 5, holdings[0].Quantity)
}

// --- Middleware helpers ---

func TestSafeStr(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", safeStr(nil))
	assert.Equal(t, "hello", safeStr("  hello  "))
	assert.Equal(t, "42", safeStr(42))
}

func TestPaperTextResult(t *testing.T) {
	t.Parallel()
	r := paperTextResult("Position already flat")
	assert.NotNil(t, r)
}

func TestPaperResult_Error(t *testing.T) {
	t.Parallel()
	r, err := paperResult(nil, assert.AnError)
	require.NoError(t, err)
	assert.True(t, r.IsError)
}

func TestPaperResult_Success(t *testing.T) {
	t.Parallel()
	data := map[string]any{"order_id": "123", "status": "COMPLETE"}
	r, err := paperResult(data, nil)
	require.NoError(t, err)
	assert.False(t, r.IsError)
}

// --- Position tracking edge cases ---

func TestShortPosition(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Sell to create short (MIS allows short).
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	positions, _ := store.GetPositions(testEmail)
	require.Len(t, positions, 1)
	assert.Equal(t, -10, positions[0].Quantity)

	time.Sleep(time.Millisecond)
	// Add to short.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)

	positions, _ = store.GetPositions(testEmail)
	require.Len(t, positions, 1)
	assert.Equal(t, -15, positions[0].Quantity)

	time.Sleep(time.Millisecond)
	// Cover and flip to long: buy 20.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 20,
	})
	require.NoError(t, err)

	positions, _ = store.GetPositions(testEmail)
	require.Len(t, positions, 1)
	assert.Equal(t, 5, positions[0].Quantity)
}

func TestCloseToZero(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	time.Sleep(time.Millisecond)
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	positions, err := store.GetPositions(testEmail)
	require.NoError(t, err)
	assert.Empty(t, positions, "position should be removed when qty is 0")
}

// --- Validation ---

func TestPlaceOrder_Validation(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Missing exchange.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"tradingsymbol": "RELIANCE", "transaction_type": "BUY",
		"order_type": "MARKET", "product": "CNC", "quantity": 10,
	})
	require.Error(t, err)

	// Invalid transaction type.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "INVALID", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.Error(t, err)

	// Zero quantity.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 0,
	})
	require.Error(t, err)

	// Unsupported order type.
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "FOK",
		"product": "CNC", "quantity": 10,
	})
	require.Error(t, err)
}

// --- SL / SL-M placement ---

func TestPlaceOrder_SL(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "SL",
		"product": "MIS", "quantity": 5, "price": 2600.0, "trigger_price": 2550.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])
}

func TestPlaceOrder_SLM(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "SL-M",
		"product": "MIS", "quantity": 5, "trigger_price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])
}

// --- LIMIT insufficient cash ---

func TestPlaceOrder_LimitInsufficientCash(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 100))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])
}

// --- Sell LIMIT immediate fill ---

func TestPlaceOrder_SellLimitImmediate(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	time.Sleep(time.Millisecond)
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 10, "price": 2400.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", result["status"])
}

// --- No LTP provider ---

func TestPlaceOrder_NoLTPProvider(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil) // no LTP provider
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)
	assert.Equal(t, "REJECTED", result["status"])
}

// --- ModifyOrder ---

func TestModifyOrder(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 5, "price": 2400.0,
	})
	require.NoError(t, err)
	orderID := result["order_id"].(string)

	modResult, err := engine.ModifyOrder(testEmail, orderID, map[string]any{"price": 2300.0})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", modResult["status"])
}

func TestModifyOrder_WrongUser(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, _ := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 5, "price": 2400.0,
	})
	orderID := result["order_id"].(string)

	_, err := engine.ModifyOrder("other@example.com", orderID, map[string]any{"price": 2300.0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not belong")
}

// --- Holdings sell without holding ---

func TestHoldings_SellWithoutHolding(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no holding")
}

// --- Status ---

func TestStatus_NotConfigured(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	status, err := engine.Status("nobody@example.com")
	require.NoError(t, err)
	assert.Equal(t, false, status["enabled"])
}

// --- Enable validation ---

func TestEnable_InvalidCash(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	err := engine.Enable(testEmail, 0)
	require.Error(t, err)
	err = engine.Enable(testEmail, -100)
	require.Error(t, err)
}

// --- GetMargins not enabled ---

func TestGetMargins_NotEnabled(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	_, err := engine.GetMargins("nobody@example.com")
	require.Error(t, err)
}

// --- CancelOrder already complete ---

func TestCancelOrder_AlreadyComplete(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)
	orderID := result["order_id"].(string)

	_, err = engine.CancelOrder(testEmail, orderID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot cancel")
}

// --- PlaceOrder not enabled ---

func TestPlaceOrder_NotEnabled(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	_, err := engine.PlaceOrder("nobody@example.com", map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

// --- Middleware internal handlers ---

func TestHandleWrite_PlaceOrder(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleWrite(engine, testEmail, "place_order", map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleWrite_ModifyOrder(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	res, _ := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 5, "price": 2400.0,
	})
	orderID := res["order_id"].(string)

	result, err := handleWrite(engine, testEmail, "modify_order", map[string]any{
		"order_id": orderID, "price": 2300.0,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleWrite_CancelOrder(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	res, _ := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 5, "price": 2400.0,
	})
	orderID := res["order_id"].(string)

	result, err := handleWrite(engine, testEmail, "cancel_order", map[string]any{
		"order_id": orderID,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleWrite_GTTNotSupported(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleWrite(engine, testEmail, "place_gtt_order", map[string]any{})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleWrite_Unknown(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := handleWrite(engine, testEmail, "unknown_tool", map[string]any{})
	require.Error(t, err)
}

func TestHandleRead_Holdings(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_holdings", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleRead_Positions(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_positions", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleRead_Orders(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_orders", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleRead_Margins(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_margins", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleRead_OrderHistory(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)

	orders, _ := engine.store.GetOrders(testEmail)
	require.NotEmpty(t, orders)

	result, err := handleRead(engine, testEmail, "get_order_history", map[string]any{
		"order_id": orders[0].OrderID,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleRead_Unknown(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := handleRead(engine, testEmail, "unknown_tool", nil)
	require.Error(t, err)
}

func TestHandleGetTrades(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)

	result, err := handleGetTrades(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleGetTrades_NoTrades(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleGetTrades(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleClosePosition(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy to create a position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE", "product": "MIS",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}

func TestHandleClosePosition_NotFound(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
	})
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleCloseAllPositions(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500, "NSE:INFY": 1500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, _ = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	time.Sleep(time.Millisecond)
	_, _ = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})

	result, err := handleCloseAllPositions(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestHandleCloseAllPositions_NoPositions(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleCloseAllPositions(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}
