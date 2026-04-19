package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestDevMode_DeleteWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent-id",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")
}


func TestDevMode_DeleteWatchlist_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}
