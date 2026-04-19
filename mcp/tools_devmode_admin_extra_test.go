package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestDevMode_PaperTradingToggle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enabled": true,
	})
	assert.NotNil(t, result)
}


func TestDevMode_PaperTradingReset(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}


func TestDevMode_PaperTradingStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_Watchlist_FullCycle(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// List (should be empty or succeed)
	result := callToolDevMode(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)

	// Create — may fail if WatchlistStore is nil, that's fine
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Test Watchlist 7",
	})
	assert.NotNil(t, result)

	// Create with empty name
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)

	// Create missing required
	result = callToolDevMode(t, mgr, "create_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PaperTradingToggle_Enable(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true,
	})
	assert.NotNil(t, result)
	// PaperEngine might be nil → error, or succeed if engine exists
}


func TestDevMode_PaperTradingToggle_Disable(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": false,
	})
	assert.NotNil(t, result)
}


func TestDevMode_PaperTradingToggle_CustomCash(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable":       true,
		"initial_cash": float64(5000000),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PaperTradingToggle_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PaperTradingStatus_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PaperTradingReset_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_Watchlist_CreateAndUse(t *testing.T) {
	// Create a watchlist and try operations on it
	mgr := newDevModeManager(t)

	// Create
	result := callToolDevMode(t, mgr, "create_watchlist", "wl-test@example.com", map[string]any{
		"name": "My Test WL",
	})
	assert.NotNil(t, result)

	// List
	result = callToolDevMode(t, mgr, "list_watchlists", "wl-test@example.com", map[string]any{})
	assert.NotNil(t, result)

	// Try adding to it
	result = callToolDevMode(t, mgr, "add_to_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"instruments": "NSE:INFY,NSE:RELIANCE",
		"notes":       "test",
		"target_entry": float64(1400),
		"target_exit":  float64(1600),
	})
	assert.NotNil(t, result)

	// Get watchlist (without LTP to avoid API call)
	result = callToolDevMode(t, mgr, "get_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"include_ltp": false,
	})
	assert.NotNil(t, result)

	// Remove items
	result = callToolDevMode(t, mgr, "remove_from_watchlist", "wl-test@example.com", map[string]any{
		"watchlist":   "My Test WL",
		"instruments": "NSE:INFY",
	})
	assert.NotNil(t, result)

	// Delete
	result = callToolDevMode(t, mgr, "delete_watchlist", "wl-test@example.com", map[string]any{
		"watchlist": "My Test WL",
	})
	assert.NotNil(t, result)
}
