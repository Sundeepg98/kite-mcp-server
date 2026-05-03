package papertrading

import (
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
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
		FilledQuantity: 10, AveragePrice: domain.NewINR(2500.0),
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
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: domain.NewINR(2500)}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: domain.NewINR(2500)}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "BUY", Price: domain.NewINR(2500)}, 2600))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: domain.NewINR(2500)}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: domain.NewINR(2500)}, 2600))
	assert.False(t, shouldFill(&Order{OrderType: "LIMIT", TransactionType: "SELL", Price: domain.NewINR(2500)}, 2400))
}

func TestShouldFill_SL(t *testing.T) {
	t.Parallel()
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: domain.NewINR(2500)}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: domain.NewINR(2500)}, 2600))
	assert.False(t, shouldFill(&Order{OrderType: "SL", TransactionType: "BUY", TriggerPrice: domain.NewINR(2500)}, 2400))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: domain.NewINR(2500)}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: domain.NewINR(2500)}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "SL", TransactionType: "SELL", TriggerPrice: domain.NewINR(2500)}, 2600))
}

func TestShouldFill_SLM(t *testing.T) {
	t.Parallel()
	assert.True(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "BUY", TriggerPrice: domain.NewINR(2500)}, 2500))
	assert.True(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "SELL", TriggerPrice: domain.NewINR(2500)}, 2400))
	assert.False(t, shouldFill(&Order{OrderType: "SL-M", TransactionType: "BUY", TriggerPrice: domain.NewINR(2500)}, 2400))
}

func TestShouldFill_UnknownType(t *testing.T) {
	t.Parallel()
	assert.False(t, shouldFill(&Order{OrderType: "FOK", TransactionType: "BUY"}, 2500))
}

// --- determineFillPrice ---

func TestDetermineFillPrice(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 2400.0, determineFillPrice(&Order{OrderType: "LIMIT", Price: domain.NewINR(2400)}, 2500))
	assert.Equal(t, 2600.0, determineFillPrice(&Order{OrderType: "SL", Price: domain.NewINR(2600)}, 2500))
	assert.Equal(t, 2500.0, determineFillPrice(&Order{OrderType: "SL", Price: domain.NewINR(0)}, 2500))
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

// TestMonitor_StopIdempotent verifies Stop is safe to call multiple times —
// once from cleanupInitializeServices in tests, once from setupGracefulShutdown
// in production. A second close() on a nil chan panics; the sync.Once guard
// prevents that.
func TestMonitor_StopIdempotent(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, 50*time.Millisecond, logger)
	monitor.Start()
	time.Sleep(20 * time.Millisecond)
	// Calling Stop multiple times must not panic.
	monitor.Stop()
	monitor.Stop()
	monitor.Stop()
}

// TestMonitor_StopWithoutStart verifies Stop on a Monitor that was never
// Started returns immediately (does not deadlock waiting for a never-closing
// doneCh).
func TestMonitor_StopWithoutStart(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	monitor := NewMonitor(engine, 50*time.Millisecond, logger)
	done := make(chan struct{})
	go func() {
		monitor.Stop()
		close(done)
	}()
	select {
	case <-done:
		// expected — Stop returned quickly.
	case <-time.After(1 * time.Second):
		t.Fatal("Monitor.Stop() deadlocked when Start was never called")
	}
}

func TestMonitor_Tick_InsufficientCash(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 100)) // very small cash

	// Insert LIMIT order directly.
	order := &Order{
		OrderID: "PAPER_CASH_TEST", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", OrderType: "LIMIT",
		Product: "MIS", Quantity: 10, Price: domain.NewINR(2400.0),
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
		Product: "CNC", Quantity: 5, Price: domain.NewINR(2400.0),
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

// ===========================================================================
// Additional edge cases and error paths for coverage
// ===========================================================================

// handleWrite — close_position and close_all_positions cases.
func TestHandleWrite_ClosePosition(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:TCS": 3500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleWrite(engine, testEmail, "close_position", map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS", "product": "MIS",
	})
	require.NoError(t, err)
	assert.NotNil(t, result) // "No matching position found"
}

func TestHandleWrite_CloseAllPositions(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleWrite(engine, testEmail, "close_all_positions", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// handleRead — get_trades, get_order_history with valid data.
func TestHandleRead_Trades(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place and fill an order.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)

	result, err := handleRead(engine, testEmail, "get_trades", nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Content[0].(gomcp.TextContent).Text, "PAPER")
}

// handleRead — get_order_history error (non-existent order).
func TestHandleRead_OrderHistory_NotFound(t *testing.T) {
	engine, _ := testEngineWithStore(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := handleRead(engine, testEmail, "get_order_history", map[string]any{
		"order_id": "nonexistent",
	})
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

// handleClosePosition — flat position case.
func TestHandleClosePosition_FlatPosition(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:INFY": 1500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy then sell same qty to create flat position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
	})
	require.NoError(t, err)
	text := result.Content[0].(gomcp.TextContent).Text
	// Position may report as flat or may not match (positions with qty=0
	// are logically flat).
	assert.True(t, strings.Contains(text, "flat") || strings.Contains(text, "No matching"),
		"expected flat or no-match message, got: %s", text)
}

// handleCloseAllPositions with short position (negative qty).
func TestHandleCloseAllPositions_ShortPosition(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:SBIN": 600})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Sell to create short position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 5,
	})
	require.NoError(t, err)

	result, err := handleCloseAllPositions(engine, testEmail)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// paperResult with JSON marshal error (channel cannot be marshaled).
func TestPaperResult_MarshalError(t *testing.T) {
	result, err := paperResult(make(chan int), nil)
	require.NoError(t, err) // error is returned in result, not as Go error
	assert.True(t, result.IsError)
}

// Status with positions, holdings, and open orders.
func TestStatus_WithFullData(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{
		"NSE:RELIANCE": 2500, "NSE:TCS": 3500,
	})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Create positions, holdings, open orders.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "RELIANCE",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 5,
	})
	require.NoError(t, err)

	// LIMIT order stays open (price < LTP).
	_, err = engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "TCS",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "MIS", "quantity": 1, "price": 3000.0,
	})
	require.NoError(t, err)

	status, err := engine.Status(testEmail)
	require.NoError(t, err)
	assert.Equal(t, true, status["enabled"])
	assert.Equal(t, 1, status["positions"])
	assert.Equal(t, 1, status["holdings"])
	assert.Equal(t, 1, status["open_orders"])
}

// monitor.fill — BUY that succeeds (CNC product) exercising the full path.
func TestMonitor_Fill_BuyCNC(t *testing.T) {
	// Set high LTP so LIMIT BUY stays OPEN at placement.
	engine := testEngine(t, map[string]float64{"NSE:HDFC": 2800})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "HDFC",
		"transaction_type": "BUY", "order_type": "LIMIT",
		"product": "CNC", "quantity": 50, "price": 2700.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Drop LTP below limit price for fill.
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:HDFC": 2600}})
	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	orders, err := engine.store.GetOrders(testEmail)
	require.NoError(t, err)
	require.Len(t, orders, 1)
	assert.Equal(t, "COMPLETE", orders[0].Status)

	// CNC → holdings updated.
	holdings, err := engine.store.GetHoldings(testEmail)
	require.NoError(t, err)
	assert.Len(t, holdings, 1)

	// Cash reduced.
	acct, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.Less(t, acct.CashBalance.Float64(), 1_000_000.0)
}

// monitor.fill — SELL order (cash should increase).
func TestMonitor_Fill_SellMIS(t *testing.T) {
	engine := testEngine(t, map[string]float64{"NSE:WIPRO": 400})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy first to create position.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "WIPRO",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "MIS", "quantity": 100,
	})
	require.NoError(t, err)

	cashAfterBuy, _ := engine.store.GetAccount(testEmail)

	// Place SELL LIMIT above current LTP (stays OPEN).
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "WIPRO",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "MIS", "quantity": 50, "price": 450.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Raise LTP above SELL price to trigger fill.
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:WIPRO": 460}})
	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// Cash should increase after SELL fill.
	acctAfterSell, err := engine.store.GetAccount(testEmail)
	require.NoError(t, err)
	assert.Greater(t, acctAfterSell.CashBalance.Float64(), cashAfterBuy.CashBalance.Float64())
}

// GetMargins with active account.
func TestGetMargins_WithAccount(t *testing.T) {
	engine := testEngine(t, map[string]float64{"NSE:RELIANCE": 2500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	margins, err := engine.GetMargins(testEmail)
	require.NoError(t, err)
	m := margins.(map[string]any)
	eq := m["equity"].(map[string]any)
	avail := eq["available"].(map[string]any)
	assert.Equal(t, 1_000_000.0, avail["cash"])
}

// ResetAccount clears everything.
// monitor.fill error paths — call fill directly with a closed DB to exercise
// each error branch (GetAccount, UpdateOrderStatus, UpdateCashBalance, etc.).
func TestMonitor_Fill_GetAccountError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	order := &Order{
		OrderID: "PAPER_FILL_TEST_1", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "FILL",
		TransactionType: "BUY", OrderType: "LIMIT", Product: "MIS",
		Quantity: 10, Price: domain.NewINR(100.0), Status: "OPEN",
	}

	// Close DB so GetAccount fails inside fill.
	db.Close()

	monitor := NewMonitor(engine, time.Second, logger)
	monitor.fill(order, 100.0) // Should not panic; error logged.
}

func TestMonitor_Fill_UpdateOrderStatusError(t *testing.T) {
	// With closed DB, GetAccount fails inside fill, covering the first error branch.
	// The deeper error branches (UpdateOrderStatus, UpdateCashBalance, etc.)
	// require the DB to fail mid-operation which is not possible with SQLite
	// without a mock store interface. Those branches are documented as
	// untestable without architecture changes (Store is a concrete type).
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	order := &Order{
		OrderID: "PAPER_FILL_DBERR", Email: testEmail,
		Exchange: "NSE", Tradingsymbol: "FILL",
		TransactionType: "BUY", OrderType: "LIMIT", Product: "CNC",
		Quantity: 1, Price: domain.NewINR(100.0), Status: "OPEN",
		PlacedAt: time.Now().UTC(),
	}
	require.NoError(t, store.InsertOrder(order))
	db.Close()

	monitor := NewMonitor(engine, time.Second, logger)
	monitor.fill(order, 100.0) // GetAccount fails → logs, returns.
}

func TestMonitor_Fill_CNC_SellingReducesHoldings(t *testing.T) {
	engine := testEngine(t, map[string]float64{"NSE:HDFC": 2800})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Buy CNC shares.
	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "HDFC",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 100,
	})
	require.NoError(t, err)

	// Place CNC SELL LIMIT above LTP (stays OPEN).
	result, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "HDFC",
		"transaction_type": "SELL", "order_type": "LIMIT",
		"product": "CNC", "quantity": 50, "price": 2900.0,
	})
	require.NoError(t, err)
	assert.Equal(t, "OPEN", result["status"])

	// Raise LTP to trigger SELL fill.
	engine.SetLTPProvider(&mockLTP{prices: map[string]float64{"NSE:HDFC": 3000}})
	monitor := NewMonitor(engine, time.Second,
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	monitor.tick()

	// Holdings should reflect the SELL (reduced by 50).
	holdings, err := engine.store.GetHoldings(testEmail)
	require.NoError(t, err)
	require.Len(t, holdings, 1)
	assert.Equal(t, 50, holdings[0].Quantity)
}

// Status error paths — close DB to trigger store errors.
func TestStatus_DBErrors(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	db.Close()

	_, err = engine.Status(testEmail)
	require.Error(t, err)
}

// GetMargins error path.
func TestGetMargins_DBError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())

	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	db.Close()

	_, err = engine.GetMargins(testEmail)
	require.Error(t, err)
}

// Store error paths.
func TestStore_GetOpenOrders_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	db.Close()
	_, err = store.GetOpenOrders("u@t.com")
	require.Error(t, err)
}

func TestStore_GetOrder_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	db.Close()
	_, err = store.GetOrder("nonexistent")
	require.Error(t, err)
}

func TestStore_GetAllOpenOrders_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	db.Close()
	_, err = store.GetAllOpenOrders()
	require.Error(t, err)
}

func TestStore_GetPositions_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	db.Close()
	_, err = store.GetPositions("u@t.com")
	require.Error(t, err)
}

func TestStore_GetHoldings_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	db.Close()
	_, err = store.GetHoldings("u@t.com")
	require.Error(t, err)
}

func TestStore_ResetAccount_ClosedDB(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, store.InitTables())
	// Create account first, then close DB.
	require.NoError(t, store.EnableAccount(testEmail, 1_000_000))
	db.Close()
	err = store.ResetAccount(testEmail)
	require.Error(t, err)
}

// handleClosePosition with short position (BUY to close).
func TestHandleClosePosition_ShortPosition_Close(t *testing.T) {
	engine, _ := testEngineWithStore(t, map[string]float64{"NSE:SBIN": 600})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN",
		"transaction_type": "SELL", "order_type": "MARKET",
		"product": "MIS", "quantity": 10,
	})
	require.NoError(t, err)

	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "SBIN", "product": "MIS",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Content[0].(gomcp.TextContent).Text, "PAPER")
}

// handleGetTrades error path.
func TestHandleGetTrades_Error(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	db.Close()

	result, err := handleGetTrades(engine, testEmail)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

// handleClosePosition error path (GetPositions fails).
func TestHandleClosePosition_Error(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	db.Close()

	result, err := handleClosePosition(engine, testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
	})
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

// handleCloseAllPositions error path (GetPositions fails).
func TestHandleCloseAllPositions_Error(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewStore(db, logger)
	require.NoError(t, store.InitTables())
	engine := NewEngine(store, logger)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))
	db.Close()

	result, err := handleCloseAllPositions(engine, testEmail)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestResetAccount_ClearsAll(t *testing.T) {
	engine, store := testEngineWithStore(t, map[string]float64{"NSE:INFY": 1500})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	_, err := engine.PlaceOrder(testEmail, map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "order_type": "MARKET",
		"product": "CNC", "quantity": 10,
	})
	require.NoError(t, err)

	require.NoError(t, store.ResetAccount(testEmail))

	orders, _ := store.GetOrders(testEmail)
	assert.Empty(t, orders)
	positions, _ := store.GetPositions(testEmail)
	assert.Empty(t, positions)
	holdings, _ := store.GetHoldings(testEmail)
	assert.Empty(t, holdings)
	acct, _ := store.GetAccount(testEmail)
	assert.InDelta(t, 1_000_000.0, acct.CashBalance.Float64(), 0.01)
}
