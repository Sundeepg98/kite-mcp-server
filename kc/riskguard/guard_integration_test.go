package riskguard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// newIntegrationGuard creates a Guard backed by in-memory SQLite for persistence tests.
func newIntegrationGuard(t *testing.T) *Guard {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)
	g.SetDB(db)
	require.NoError(t, g.InitTable())
	pinClockInMarketHours(g)
	return g
}

// validSmallOrder is a baseline request that should pass all 8 checks.
// Confirmed=true is set so the new default-on require-confirm gate is not
// the reason for any block in these integration tests — they target the
// OTHER safety checks specifically.
func validSmallOrder(email string) OrderCheckRequest {
	return OrderCheckRequest{
		Email:           email,
		ToolName:        "place_order",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        5,
		Price: domain.NewINR(1500),
		OrderType:       "LIMIT",
		Confirmed:       true,
	}
}

// ---------------------------------------------------------------------------
// Full chain: all 8 checks pass for a valid small order
// ---------------------------------------------------------------------------

func TestFullChain_AllChecksPass(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "trader@example.com"

	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:INFY": 1800,
	}})

	req := validSmallOrder(email)

	r := g.CheckOrderCtx(context.Background(), req)
	assert.True(t, r.Allowed, "valid small order should pass all 8 checks")
	assert.Empty(t, r.Message)
	assert.Equal(t, RejectionReason(""), r.Reason)

	// Record it and verify state tracks correctly.
	g.RecordOrder(email, req)

	status := g.GetUserStatus(email)
	assert.Equal(t, 1, status.DailyOrderCount)
	assert.InDelta(t, 5*1500.0, status.DailyPlacedValue.Float64(), 0.01)
	assert.False(t, status.IsFrozen)
}

// ---------------------------------------------------------------------------
// Check 1: Kill switch blocks when user is frozen
// ---------------------------------------------------------------------------

func TestFullChain_KillSwitchBlocks(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "frozen@example.com"

	// Freeze the user with a reason.
	g.Freeze(email, "compliance@firm.com", "Suspicious activity detected")

	r := g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonTradingFrozen, r.Reason)
	assert.Contains(t, r.Message, "Suspicious activity detected")

	// Verify freeze persisted in DB by reloading.
	g2 := NewGuard(slog.Default())
	g2.SetDB(g.db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())
	assert.True(t, g2.IsFrozen(email))

	// Unfreeze and verify order passes.
	g.Unfreeze(email)
	r = g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.True(t, r.Allowed)
}

// ---------------------------------------------------------------------------
// Check 2: Order value limit blocks orders > Rs 5L
// ---------------------------------------------------------------------------

func TestFullChain_OrderValueLimit(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "bigspender@example.com"

	// Tightened Free-tier cap: Rs 50,000 per order (was Rs 5,00,000). The
	// table cases below were rescaled by 10x to match the new default.
	// Confirmed=true on every request isolates the order-value check.
	tests := []struct {
		name    string
		qty     int
		price   float64
		allowed bool
		reason  RejectionReason
	}{
		{"exactly at limit passes (strict >)", 5, 10000, true, ""},       // 5*10000 = 50000 = limit
		{"just over limit", 6, 10000, false, ReasonOrderValue},           // 60000 > 50000
		{"way over limit", 10, 10000, false, ReasonOrderValue},           // 100000 > 50000
		{"MARKET order (price 0) passes", 100000, 0, true, ""},           // price=0 skips check
		{"small order passes", 10, 100, true, ""},                        // 1000 < 50000
		{"single expensive share", 1, 60000, false, ReasonOrderValue},    // 60000 > 50000
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := OrderCheckRequest{
				Email: email, ToolName: "place_order",
				Exchange: "NSE", Tradingsymbol: "TEST",
				TransactionType: "BUY",
				Quantity: tc.qty, Price: domain.NewINR(tc.price),
				OrderType: "LIMIT",
				Confirmed: true,
			}
			if tc.price == 0 {
				req.OrderType = "MARKET"
			}
			r := g.CheckOrderCtx(context.Background(), req)
			assert.Equal(t, tc.allowed, r.Allowed, tc.name)
			if !tc.allowed {
				assert.Equal(t, tc.reason, r.Reason, tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Check 3: Quantity limit blocks orders exceeding freeze qty
// ---------------------------------------------------------------------------

func TestFullChain_QuantityLimit(t *testing.T) {
	g := newIntegrationGuard(t)

	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:RELIANCE": 1800,
		"NFO:NIFTY":    900,
	}})

	// Disable auto-freeze for this test to avoid circuit breaker interference across subtests.
	baseEmail := "qty"

	tests := []struct {
		name      string
		exchange  string
		symbol    string
		qty       int
		price     float64
		allowed   bool
	}{
		{"under freeze qty", "NSE", "RELIANCE", 100, 100, true},
		{"at freeze qty", "NSE", "RELIANCE", 1800, 0, true},       // price=0 to skip value check
		{"over freeze qty", "NSE", "RELIANCE", 1801, 0, false},    // price=0 to skip value check
		{"NFO under", "NFO", "NIFTY", 900, 0, true},
		{"NFO over", "NFO", "NIFTY", 901, 0, false},
		{"unknown instrument (fail open)", "NSE", "UNKNOWN", 10, 100, true},
		{"no exchange (fail open)", "", "RELIANCE", 10, 100, true},
		{"negative qty blocked", "NSE", "RELIANCE", -1, 0, false},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use a unique email per subtest to prevent circuit breaker interference.
			email := fmt.Sprintf("%s%d@example.com", baseEmail, i)
			g.mu.Lock()
			g.limits[email] = &UserLimits{AutoFreezeOnLimitHit: false}
			g.mu.Unlock()

			orderType := "LIMIT"
			if tc.price == 0 {
				orderType = "MARKET"
			}
			req := OrderCheckRequest{
				Email: email, ToolName: "place_order",
				Exchange: tc.exchange, Tradingsymbol: tc.symbol,
				TransactionType: "BUY", Quantity: tc.qty,
				Price: domain.NewINR(tc.price), OrderType: orderType,
			}
			r := g.CheckOrderCtx(context.Background(), req)
			assert.Equal(t, tc.allowed, r.Allowed, tc.name)
			if !tc.allowed {
				assert.Equal(t, ReasonQuantityLimit, r.Reason, tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Check 4: Daily order count limit (Free-tier default: 20/day, was 200/day)
// ---------------------------------------------------------------------------

func TestFullChain_DailyOrderLimit(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "dailylimit@example.com"

	// Use system default: 20/day.
	// Simulate 20 orders already placed.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DailyOrderCount = 20
	tracker.DayResetAt = g.clock()
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonDailyOrderLimit, r.Reason)
	assert.Contains(t, r.Message, "20")

	// Reduce count by 1 — should pass.
	g.mu.Lock()
	tracker.DailyOrderCount = 19
	g.mu.Unlock()

	r = g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.True(t, r.Allowed)
}

func TestFullChain_DailyOrderLimit_CustomPerUser(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "lowlimit@example.com"

	// Set a per-user limit of 5 orders/day. Set high rate limit and disable duplicate window.
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxOrdersPerDay:      5,
		MaxOrdersPerMinute:   100,
		DuplicateWindowSecs:  0, // disable duplicate detection for this test
		AutoFreezeOnLimitHit: true,
	}
	g.mu.Unlock()

	// Place 5 orders with varying symbols to avoid any edge cases.
	symbols := []string{"INFY", "TCS", "RELIANCE", "SBIN", "HDFC"}
	for i := 0; i < 5; i++ {
		req := OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: symbols[i],
			TransactionType: "BUY", Quantity: 1,
			Price: domain.NewINR(100), OrderType: "LIMIT",
		}
		r := g.CheckOrderCtx(context.Background(), req)
		require.True(t, r.Allowed, "order %d should pass", i+1)
		g.RecordOrder(email, req)
	}

	// 6th should be blocked.
	r := g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonDailyOrderLimit, r.Reason)
}

// ---------------------------------------------------------------------------
// Check 5: Rate limit (10/min)
// ---------------------------------------------------------------------------

func TestFullChain_RateLimit(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "ratelimit@example.com"

	// Use system default: 10/min.
	// Simulate 10 orders placed in the last 30 seconds.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	now := time.Now()
	for i := 0; i < 10; i++ {
		tracker.RecentOrders = append(tracker.RecentOrders, now.Add(-time.Duration(i)*time.Second))
	}
	tracker.DayResetAt = now
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonRateLimit, r.Reason)
	assert.Contains(t, r.Message, "limit: 10")
}

func TestFullChain_RateLimit_OldOrdersPruned(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "rateprune@example.com"

	// All 10 orders are > 60 seconds old — should be pruned.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Now()
	for i := 0; i < 10; i++ {
		tracker.RecentOrders = append(tracker.RecentOrders, time.Now().Add(-2*time.Minute))
	}
	g.mu.Unlock()

	r := g.CheckOrderCtx(context.Background(), validSmallOrder(email))
	assert.True(t, r.Allowed, "old orders should be pruned and not count toward rate limit")
}

// ---------------------------------------------------------------------------
// Check 6: Duplicate order detection (30s window)
// ---------------------------------------------------------------------------

func TestFullChain_DuplicateOrder(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "dup@example.com"

	// 50 * 800 = 40000 < new 50k per-order cap. Confirmed=true bypasses the
	// new default-on require-confirm gate so this test isolates duplicate
	// detection.
	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", Quantity: 50,
		Price: domain.NewINR(800), OrderType: "LIMIT",
		Confirmed: true,
	}

	// First order passes.
	r := g.CheckOrderCtx(context.Background(), req)
	assert.True(t, r.Allowed)
	g.RecordOrder(email, req)

	// Identical order within 30s blocked.
	r = g.CheckOrderCtx(context.Background(), req)
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonDuplicateOrder, r.Reason)
	assert.Contains(t, r.Message, "BUY NSE SBIN qty 50")

	// Different symbol passes.
	diffReq := req
	diffReq.Tradingsymbol = "HDFC"
	r = g.CheckOrderCtx(context.Background(), diffReq)
	assert.True(t, r.Allowed)

	// Same symbol, different direction passes.
	sellReq := req
	sellReq.TransactionType = "SELL"
	r = g.CheckOrderCtx(context.Background(), sellReq)
	assert.True(t, r.Allowed)

	// After window expires, same order passes.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	for i := range tracker.RecentParams {
		tracker.RecentParams[i].PlacedAt = time.Now().Add(-60 * time.Second)
	}
	g.mu.Unlock()

	r = g.CheckOrderCtx(context.Background(), req)
	assert.True(t, r.Allowed)
}

// ---------------------------------------------------------------------------
// Check 7: Daily value limit (Free-tier default: Rs 2L, was Rs 10L)
// ---------------------------------------------------------------------------

func TestFullChain_DailyValueLimit(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "valueday@example.com"

	// System default: Rs 2,00,000 daily value (was Rs 10,00,000).
	// Simulate Rs 1,90,000 already placed.
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DailyPlacedValue = domain.NewINR(190000)
	tracker.DayResetAt = g.clock()
	g.mu.Unlock()

	// An order for Rs 12,000 would push total to Rs 2,02,000 > Rs 2,00,000
	// and also passes the per-order Rs 50,000 cap.
	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", Quantity: 4, Price: domain.NewINR(3000),
		OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonDailyValueLimit, r.Reason)
	assert.Contains(t, r.Message, "exceeds daily limit")

	// An order for Rs 8,000 fits: 190000 + 8000 = 198000 < 200000.
	r = g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE",
		TransactionType: "BUY", Quantity: 4, Price: domain.NewINR(2000),
		OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed)
}

func TestFullChain_DailyValueLimit_MarketOrderSkips(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "marketval@example.com"

	// Simulate Rs 1,99,999 already placed (just under new Rs 2L cap).
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DailyPlacedValue = domain.NewINR(199999)
	tracker.DayResetAt = time.Now()
	g.mu.Unlock()

	// MARKET order with price=0 should skip daily value check.
	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "TCS",
		TransactionType: "BUY", Quantity: 1000, Price: domain.Money{},
		OrderType: "MARKET",
		Confirmed: true,
	})
	assert.True(t, r.Allowed, "MARKET orders (price=0) should skip daily value check")
}

// ---------------------------------------------------------------------------
// Check 8: Auto-freeze circuit breaker
// ---------------------------------------------------------------------------

func TestFullChain_AutoFreezeCircuitBreaker(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "circuit@example.com"

	// Set a low order value limit to easily trigger rejections.
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(1000), // Rs 1,000
		AutoFreezeOnLimitHit: true,
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "TEST",
		TransactionType: "BUY", Quantity: 10, Price: domain.NewINR(200),
		OrderType: "LIMIT", // 10*200 = 2000 > 1000
	}

	// First rejection: not frozen.
	r := g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonOrderValue, r.Reason)
	assert.False(t, g.IsFrozen(email))

	// Second rejection: still not frozen.
	r = g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, r.Allowed)
	assert.False(t, g.IsFrozen(email))

	// Third rejection: auto-freeze triggers (threshold = 3).
	r = g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email), "user should be auto-frozen after 3 rejections")
	assert.Contains(t, r.Message, "auto-frozen due to repeated violations")

	// Verify freeze metadata.
	status := g.GetUserStatus(email)
	assert.True(t, status.IsFrozen)
	assert.Equal(t, "riskguard:circuit-breaker", status.FrozenBy)

	// Subsequent order blocked by kill switch (check 1), not value limit.
	r = g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonTradingFrozen, r.Reason)

	// Verify freeze persists in DB.
	g2 := NewGuard(slog.Default())
	g2.SetDB(g.db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())
	assert.True(t, g2.IsFrozen(email))
}

func TestFullChain_AutoFreezeDisabled(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "nofreeze@example.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(1000),
		AutoFreezeOnLimitHit: false, // disabled
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 10, Price: domain.NewINR(200), OrderType: "LIMIT",
	}

	// 5 rejections — none should freeze.
	for i := 0; i < 5; i++ {
		r := g.CheckOrderCtx(context.Background(), overLimitReq)
		assert.False(t, r.Allowed)
		assert.NotContains(t, r.Message, "auto-frozen")
	}
	assert.False(t, g.IsFrozen(email))
}

func TestFullChain_AutoFreeze_OldRejectionsExpire(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "expiry@example.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(1000),
		AutoFreezeOnLimitHit: true,
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 10, Price: domain.NewINR(200), OrderType: "LIMIT",
	}

	// Two rejections, then move them outside the 5-minute window.
	g.CheckOrderCtx(context.Background(), overLimitReq)
	g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, g.IsFrozen(email))

	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	for i := range tracker.RecentRejections {
		tracker.RecentRejections[i] = time.Now().Add(-10 * time.Minute)
	}
	g.mu.Unlock()

	// One more rejection — should NOT trigger freeze (only 1 in window).
	g.CheckOrderCtx(context.Background(), overLimitReq)
	assert.False(t, g.IsFrozen(email), "old rejections outside window should not count")
}

// ---------------------------------------------------------------------------
// Integration: check order priority (earlier check blocks before later check)
// ---------------------------------------------------------------------------

func TestFullChain_FreezeBlocksBeforeOtherChecks(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "priority@example.com"

	g.Freeze(email, "admin", "compliance hold")

	// Even a massive illegal order should return "frozen", not "order value".
	r := g.CheckOrderCtx(context.Background(), OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 1000000, Price: domain.NewINR(100000), OrderType: "LIMIT",
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonTradingFrozen, r.Reason, "kill switch should block before value check")
}

// ---------------------------------------------------------------------------
// Integration: RecordOrder updates all trackers
// ---------------------------------------------------------------------------

func TestFullChain_RecordOrder_UpdatesAllTrackers(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "recorder@example.com"

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "TCS",
		TransactionType: "BUY", Quantity: 10, Price: domain.NewINR(3500),
		OrderType: "LIMIT",
	}

	g.RecordOrder(email, req)
	g.RecordOrder(email, req)
	g.RecordOrder(email, req)

	g.mu.RLock()
	tracker := g.trackers[email]
	assert.Equal(t, 3, tracker.DailyOrderCount)
	assert.Equal(t, 3, len(tracker.RecentOrders))
	assert.Equal(t, 3, len(tracker.RecentParams))
	assert.InDelta(t, 3*10*3500.0, tracker.DailyPlacedValue.Float64(), 0.01)
	g.mu.RUnlock()
}

// ---------------------------------------------------------------------------
// Concurrency: multiple goroutines checking and recording orders
// ---------------------------------------------------------------------------

func TestFullChain_ConcurrentAccess(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "concurrent@example.com"

	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex

	// 50 goroutines each trying to place an order.
	// Confirmed=true so the new require-confirm gate isn't the block reason;
	// we're stress-testing concurrency of the limit checks specifically.
	for range 50 {
		wg.Go(func() {
			req := OrderCheckRequest{
				Email: email, ToolName: "place_order",
				Exchange: "NSE", Tradingsymbol: "INFY",
				TransactionType: "BUY", Quantity: 1,
				Price: domain.NewINR(1500), OrderType: "LIMIT",
				Confirmed: true,
			}
			r := g.CheckOrderCtx(context.Background(), req)
			if r.Allowed {
				g.RecordOrder(email, req)
			} else {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	status := g.GetUserStatus(email)
	// With Free-tier defaults (20/day, 10/min, duplicate 30s window), most
	// will be rejected; we assert only that every goroutine either succeeded
	// or was blocked — the two counts must sum to 50 (concurrency invariant).
	assert.Equal(t, 50, status.DailyOrderCount+errCount,
		"every goroutine should end in either success or rejection")
}

// ---------------------------------------------------------------------------
// DB persistence: freeze/unfreeze survives reload
// ---------------------------------------------------------------------------

func TestFullChain_DBPersistence(t *testing.T) {
	g := newIntegrationGuard(t)
	email := "persist@example.com"

	// Set per-user limits, freeze, and verify persistence.
	g.Freeze(email, "admin", "DB test")

	// Create a new guard reading from the same DB.
	g2 := NewGuard(slog.Default())
	g2.SetDB(g.db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())

	assert.True(t, g2.IsFrozen(email))

	limits := g2.GetEffectiveLimits(email)
	assert.Equal(t, "admin", limits.FrozenBy)
	assert.Equal(t, "DB test", limits.FrozenReason)
}

// ---------------------------------------------------------------------------
// Email case insensitivity
// ---------------------------------------------------------------------------

func TestFullChain_EmailCaseInsensitive(t *testing.T) {
	g := newIntegrationGuard(t)

	g.Freeze("User@Example.COM", "admin", "case test")
	assert.True(t, g.IsFrozen("user@example.com"))
	assert.True(t, g.IsFrozen("USER@EXAMPLE.COM"))

	g.Unfreeze("USER@EXAMPLE.COM")
	assert.False(t, g.IsFrozen("user@example.com"))
}

// TestLoadLimits_ScanError triggers the rows.Scan error path (guard.go:730-732)
// by dropping the real table, recreating it with all column names, and inserting
// a row where an INTEGER column contains a non-numeric string (causing Scan to fail).
func TestLoadLimits_ScanError(t *testing.T) {
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Drop the real table and recreate with all expected column names but
	// no type constraints. Then insert a row where max_orders_per_day holds
	// NULL. The Go Scan into int will fail.
	require.NoError(t, db.ExecDDL(`DROP TABLE risk_limits`))
	require.NoError(t, db.ExecDDL(`CREATE TABLE risk_limits (
		email TEXT,
		max_single_order_inr TEXT,
		max_orders_per_day TEXT,
		max_orders_per_minute TEXT,
		duplicate_window_secs TEXT,
		max_daily_value_inr TEXT,
		auto_freeze_on_limit_hit TEXT,
		require_confirm_all_orders TEXT,
		trading_frozen TEXT,
		frozen_at TEXT,
		frozen_by TEXT,
		frozen_reason TEXT
	)`))
	// Insert a row where integer columns contain NULL (scan into int fails).
	require.NoError(t, db.ExecInsert(
		`INSERT INTO risk_limits (email) VALUES ('bad@test.com')`))

	err = g.LoadLimits()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan risk_limits")
}
