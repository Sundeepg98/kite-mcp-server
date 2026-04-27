package papertrading

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// --- toInt / toFloat coverage ---


// --- GetOrders when disabled ---
func TestGetOrders_WhenDisabled(t *testing.T) {
	t.Parallel()
	engine, _ := testEngineWithStore(t, map[string]float64{})
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	// Place some orders.
	res, _ := engine.GetOrders(testEmail)
	orders := res.([]map[string]any)
	assert.Empty(t, orders)
}


// --- GetPositions with no LTP provider ---
func TestGetPositions_NoLTPProvider(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	engine, _ := testEngineWithStore(t, nil)
	require.NoError(t, engine.Enable(testEmail, 1_000_000))

	holdingsResp, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)
	holdings := holdingsResp.([]map[string]any)
	assert.Empty(t, holdings)
}


// --- LTP provider error in GetPositions/GetHoldings ---
func TestGetPositions_LTPError(t *testing.T) {
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

	// Insert a position directly.
	require.NoError(t, store.UpsertPosition(&Position{
		Email: testEmail, Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Product: "MIS", Quantity: 10, AveragePrice: 2500, LastPrice: domain.NewINR(2500),
	}))

	// Should still return positions even if LTP fails.
	posResp, err := engine.GetPositions(testEmail)
	require.NoError(t, err)
	posMap := posResp.(map[string]any)
	day := posMap["day"].([]map[string]any)
	assert.Len(t, day, 1)
}


func TestGetHoldings_LTPError(t *testing.T) {
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

	// Insert a holding directly.
	require.NoError(t, store.UpsertHolding(&Holding{
		Email: testEmail, Exchange: "NSE", Tradingsymbol: "RELIANCE",
		Quantity: 10, AveragePrice: 2500, LastPrice: domain.NewINR(2500),
	}))

	holdingsResp, err := engine.GetHoldings(testEmail)
	require.NoError(t, err)
	holdings := holdingsResp.([]map[string]any)
	assert.Len(t, holdings, 1)
}


func TestGetOrders_DBError(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
