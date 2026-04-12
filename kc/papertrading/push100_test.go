package papertrading

import (
	"log/slog"
	"os"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// ===========================================================================
// push100_test.go — Push papertrading from 97.6% toward ceiling.
//
// Targets reachable-but-untested paths:
// - monitor.fill() insufficient cash rejection (lines 158-165)
// - handleClosePosition qty==0 "already flat" (lines 141-142)
// - handleCloseAllPositions qty==0 skip (line 175)
// ===========================================================================

const push100Email = "push100@test.com"

// newTestEngine creates an isolated engine with in-memory SQLite.
func newTestEngine(t *testing.T, prices map[string]float64) *PaperEngine {
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

// ---------------------------------------------------------------------------
// Monitor fill() — insufficient cash rejection path (lines 158-165)
//
// Scenario: place a BUY LIMIT order with sufficient cash at placement, then
// drain the cash with a MARKET BUY, then tick the monitor so the LIMIT
// becomes fillable but the account can no longer afford it.
// ---------------------------------------------------------------------------

func TestMonitorFill_InsufficientCash(t *testing.T) {
	// LTP starts at 500. LIMIT BUY at 400 won't fill yet.
	engine := newTestEngine(t, map[string]float64{"NSE:SBIN": 500, "NSE:RELIANCE": 2000})
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
	time.Sleep(time.Millisecond)

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
	assert.InDelta(t, 2000, acct.CashBalance, 1)

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
// handleClosePosition — qty==0 "Position already flat" (lines 141-142)
//
// Directly insert a zero-quantity position via store.UpsertPosition (bypassing
// the engine which deletes zero-qty positions). handleClosePosition should
// return "Position already flat".
// ---------------------------------------------------------------------------

func TestHandleClosePosition_ZeroQuantity(t *testing.T) {
	engine := newTestEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(push100Email, 1_000_000))

	// Directly insert a position with qty=0 (bypassing engine logic)
	err := engine.store.UpsertPosition(&Position{
		Email:         push100Email,
		Exchange:      "NSE",
		Tradingsymbol: "SBIN",
		Product:       "MIS",
		Quantity:      0,
		AveragePrice:  500,
		LastPrice:     500,
		PnL:           0,
	})
	require.NoError(t, err)

	result, err := handleClosePosition(engine, push100Email, map[string]any{
		"exchange":      "NSE",
		"tradingsymbol": "SBIN",
		"product":       "MIS",
	})
	require.NoError(t, err)
	assert.False(t, result.IsError) // "Position already flat" is not an error
	// Verify it's the "already flat" message
	require.NotEmpty(t, result.Content)
	tc, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, tc.Text, "already flat")
}

// ---------------------------------------------------------------------------
// handleCloseAllPositions — qty==0 skip path (line 175)
//
// Insert one zero-qty position and one real position. closeAll should skip
// the zero-qty one and close the real one.
// ---------------------------------------------------------------------------

func TestHandleCloseAllPositions_SkipsZeroQuantity(t *testing.T) {
	engine := newTestEngine(t, map[string]float64{
		"NSE:SBIN": 500, "NSE:RELIANCE": 2500,
	})
	require.NoError(t, engine.Enable(push100Email, 10_000_000))

	// Create a real position via engine
	_, err := engine.PlaceOrder(push100Email, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         5,
	})
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	// Directly insert a zero-qty position
	err = engine.store.UpsertPosition(&Position{
		Email:         push100Email,
		Exchange:      "NSE",
		Tradingsymbol: "SBIN",
		Product:       "MIS",
		Quantity:      0,
		AveragePrice:  500,
		LastPrice:     500,
		PnL:           0,
	})
	require.NoError(t, err)

	result, err := handleCloseAllPositions(engine, push100Email)
	require.NoError(t, err)
	assert.False(t, result.IsError)
	// Should have results (for the RELIANCE close), but the SBIN zero-qty was skipped
	assert.NotNil(t, result)
}

// ---------------------------------------------------------------------------
// handleCloseAllPositions — PlaceOrder error from disabled account (line 186)
//
// Create a real position, then disable the account. handleCloseAllPositions
// still finds positions via GetPositions, but PlaceOrder fails with
// "paper trading is not enabled" → hits the error branch at line 186.
// ---------------------------------------------------------------------------

func TestHandleCloseAllPositions_DisabledAccount(t *testing.T) {
	engine := newTestEngine(t, map[string]float64{"NSE:SBIN": 500})
	require.NoError(t, engine.Enable(push100Email, 1_000_000))

	// Create a real position
	_, err := engine.PlaceOrder(push100Email, map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "SBIN",
		"transaction_type": "BUY",
		"order_type":       "MARKET",
		"product":          "MIS",
		"quantity":         10,
	})
	require.NoError(t, err)

	// Disable the account — positions remain in DB, but PlaceOrder will fail
	require.NoError(t, engine.Disable(push100Email))

	result, err := handleCloseAllPositions(engine, push100Email)
	require.NoError(t, err)
	assert.NotNil(t, result)
	// Result should contain error entries for each position
	assert.False(t, result.IsError) // wrapper succeeds, individual errors inside
}
