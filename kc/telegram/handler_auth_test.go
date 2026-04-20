package telegram

// Tests for handler functions that interact with Kite API via a fake HTTP server.
// These cover the handler body code paths that were at low coverage:
// handlePrice, handlePortfolio, handlePositions, handleOrders,
// handlePnL, handlePrices, handleMyWatchlist, executeConfirmedOrder.

import (
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// fakeKiteAPI type is defined in handler_test.go (shared across split files).


// ===========================================================================
// handleStatus — covered via existing test, but adding expired/valid paths
// ===========================================================================
func TestHandleStatus_ValidCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "test-key-ABCD"
	mgr.accessTokens["user@test.com"] = "test-token"
	mgr.tokenValid["user@test.com"] = true

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Status") {
		t.Errorf("expected 'Status', got: %s", result)
	}
	if !strings.Contains(result, "ABCD") {
		t.Errorf("expected last 4 of API key, got: %s", result)
	}
	if !strings.Contains(result, "Valid") {
		t.Errorf("expected 'Valid', got: %s", result)
	}
}


func TestHandleStatus_ExpiredCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "some-key"
	mgr.accessTokens["user@test.com"] = "old-token"
	mgr.tokenValid["user@test.com"] = false

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Expired") {
		t.Errorf("expected 'Expired', got: %s", result)
	}
}


func TestHandleStatus_MissingCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "nobody@test.com")
	if !strings.Contains(result, "Not configured") {
		t.Errorf("expected 'Not configured', got: %s", result)
	}
	if !strings.Contains(result, "Not found") {
		t.Errorf("expected 'Not found', got: %s", result)
	}
}
