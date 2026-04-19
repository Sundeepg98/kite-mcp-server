package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Watchlist tools: pre-session validation
// ---------------------------------------------------------------------------
func TestCreateWatchlist_MissingName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "create_watchlist without name should fail")
	assertResultContains(t, result, "is required")
}


func TestCreateWatchlist_EmptyName(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "trader@example.com", map[string]any{
		"name": "   ", // whitespace only
	})
	assert.True(t, result.IsError, "create_watchlist with empty name should fail")
	assertResultContains(t, result, "cannot be empty")
}


func TestCreateWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "create_watchlist", "", map[string]any{
		"name": "Tech Stocks",
	})
	assert.True(t, result.IsError, "create_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestAddToWatchlist_MissingParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "add_to_watchlist without params should fail")
	assertResultContains(t, result, "is required")
}


func TestAddToWatchlist_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "trader@example.com", map[string]any{
		"watchlist": "my-list",
		// instruments missing
	})
	assert.True(t, result.IsError, "add_to_watchlist without instruments should fail")
	assertResultContains(t, result, "is required")
}


func TestAddToWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "add_to_watchlist", "", map[string]any{
		"watchlist":   "my-list",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError, "add_to_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestDeleteWatchlist_MissingWatchlist(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "delete_watchlist without watchlist should fail")
	assertResultContains(t, result, "is required")
}


func TestRemoveFromWatchlist_MissingParams(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "remove_from_watchlist without params should fail")
	assertResultContains(t, result, "is required")
}


func TestGetWatchlist_MissingWatchlist(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_watchlist without watchlist should fail")
	assertResultContains(t, result, "is required")
}


func TestGetWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_watchlist", "", map[string]any{
		"watchlist": "my-list",
	})
	assert.True(t, result.IsError, "get_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestListWatchlists_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "list_watchlists", "", map[string]any{})
	assert.True(t, result.IsError, "list_watchlists without email should fail")
	assertResultContains(t, result, "Email required")
}


// ---------------------------------------------------------------------------
// Watchlist: additional edge cases
// ---------------------------------------------------------------------------
func TestDeleteWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_watchlist", "", map[string]any{
		"watchlist": "my-list",
	})
	assert.True(t, result.IsError, "delete_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestRemoveFromWatchlist_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "remove_from_watchlist", "", map[string]any{
		"watchlist":   "my-list",
		"instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError, "remove_from_watchlist without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestAddToWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "add_to_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent", "instruments": "NSE:INFY",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


func TestRemoveFromWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "remove_from_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent", "items": "abc123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}
