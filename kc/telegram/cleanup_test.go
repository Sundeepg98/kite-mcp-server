package telegram

import (
	"testing"
	"time"
)

// TestCleanupNow_PrunesStaleRateWindow verifies that CleanupNow removes
// rate-limit entries where ALL timestamps are older than the cleanup
// interval (2 minutes).
func TestCleanupNow_PrunesStaleRateWindow(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	chatID := int64(12345)

	// Insert rate-limit entries that are all stale (older than 2 minutes).
	h.rateMu.Lock()
	h.rateWindow[chatID] = []time.Time{
		time.Now().Add(-5 * time.Minute),
		time.Now().Add(-4 * time.Minute),
		time.Now().Add(-3 * time.Minute),
	}
	h.rateMu.Unlock()

	h.CleanupNow()

	h.rateMu.Lock()
	_, exists := h.rateWindow[chatID]
	h.rateMu.Unlock()

	if exists {
		t.Fatal("stale rate-limit entries should have been cleaned up")
	}
}

// TestCleanupNow_KeepsFreshRateWindow verifies that CleanupNow does NOT
// remove rate-limit entries if at least one timestamp is recent.
func TestCleanupNow_KeepsFreshRateWindow(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	chatID := int64(67890)

	// Mix of stale and fresh entries.
	h.rateMu.Lock()
	h.rateWindow[chatID] = []time.Time{
		time.Now().Add(-5 * time.Minute), // stale
		time.Now().Add(-10 * time.Second), // fresh (within 2 minutes)
	}
	h.rateMu.Unlock()

	h.CleanupNow()

	h.rateMu.Lock()
	_, exists := h.rateWindow[chatID]
	h.rateMu.Unlock()

	if !exists {
		t.Fatal("rate-limit entries with at least one fresh timestamp should be kept")
	}
}

// TestCleanupNow_PrunesExpiredPendingOrders verifies that CleanupNow
// removes pending orders that have exceeded the TTL (60 seconds).
func TestCleanupNow_PrunesExpiredPendingOrders(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	chatID := int64(11111)

	// Insert a pending order created 2 minutes ago (well past the 60s TTL).
	h.pendingMu.Lock()
	h.pendingOrders[chatID] = &pendingOrder{
		Email:           "test@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		OrderType:       "MARKET",
		CreatedAt:       time.Now().Add(-2 * time.Minute),
	}
	h.pendingMu.Unlock()

	h.CleanupNow()

	h.pendingMu.Lock()
	_, exists := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if exists {
		t.Fatal("expired pending order should have been cleaned up")
	}
}

// TestCleanupNow_KeepsFreshPendingOrders verifies that CleanupNow does
// NOT remove pending orders that are still within the TTL.
func TestCleanupNow_KeepsFreshPendingOrders(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	chatID := int64(22222)

	// Insert a pending order created 10 seconds ago (within 60s TTL).
	h.pendingMu.Lock()
	h.pendingOrders[chatID] = &pendingOrder{
		Email:           "test@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "SELL",
		Quantity:        5,
		OrderType:       "LIMIT",
		Price:           1500,
		CreatedAt:       time.Now().Add(-10 * time.Second),
	}
	h.pendingMu.Unlock()

	h.CleanupNow()

	h.pendingMu.Lock()
	_, exists := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !exists {
		t.Fatal("fresh pending order should NOT have been cleaned up")
	}
}

// TestCleanupNow_EmptyMaps verifies that CleanupNow handles empty maps
// gracefully without panicking.
func TestCleanupNow_EmptyMaps(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	// Should not panic on empty maps.
	h.CleanupNow()

	h.rateMu.Lock()
	rateLen := len(h.rateWindow)
	h.rateMu.Unlock()

	h.pendingMu.Lock()
	pendingLen := len(h.pendingOrders)
	h.pendingMu.Unlock()

	if rateLen != 0 || pendingLen != 0 {
		t.Fatal("empty maps should remain empty after cleanup")
	}
}
