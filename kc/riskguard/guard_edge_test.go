package riskguard

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// =============================================================================
// Global Freeze: FreezeGlobal, UnfreezeGlobal, IsGloballyFrozen, GetGlobalFreezeStatus
// =============================================================================

func TestGlobalFreeze_FullLifecycle(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)

	// Initially not frozen
	assert.False(t, g.IsGloballyFrozen())
	status := g.GetGlobalFreezeStatus()
	assert.False(t, status.IsFrozen)
	assert.Empty(t, status.FrozenBy)
	assert.Empty(t, status.Reason)
	assert.True(t, status.FrozenAt.IsZero())

	// Freeze globally
	g.FreezeGlobal("admin@test.com", "market crash")
	assert.True(t, g.IsGloballyFrozen())

	status = g.GetGlobalFreezeStatus()
	assert.True(t, status.IsFrozen)
	assert.Equal(t, "admin@test.com", status.FrozenBy)
	assert.Equal(t, "market crash", status.Reason)
	assert.False(t, status.FrozenAt.IsZero())

	// Orders should be blocked (Confirmed=true so the confirmation gate is
	// not the reason; global freeze must take precedence).
	r := g.CheckOrder(OrderCheckRequest{
		Email: "user@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonGlobalFreeze, r.Reason)
	assert.Contains(t, r.Message, "globally suspended")

	// Unfreeze globally
	g.UnfreezeGlobal()
	assert.False(t, g.IsGloballyFrozen())

	status = g.GetGlobalFreezeStatus()
	assert.False(t, status.IsFrozen)
	assert.Empty(t, status.FrozenBy)
	assert.Empty(t, status.Reason)
	assert.True(t, status.FrozenAt.IsZero())

	// Orders should pass again
	r = g.CheckOrder(OrderCheckRequest{
		Email: "user@test.com", ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed)
}

func TestGlobalFreeze_BlocksBeforeUserChecks(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	g.FreezeGlobal("admin", "emergency")

	// Even a frozen user should get global freeze reason, not per-user freeze reason
	g.Freeze("user@test.com", "admin", "user-level freeze")

	r := g.CheckOrder(OrderCheckRequest{
		Email: "user@test.com", ToolName: "place_order",
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonGlobalFreeze, r.Reason)
}

// =============================================================================
// SetAutoFreezeNotifier
// =============================================================================

func TestSetAutoFreezeNotifier(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	var notifiedEmail, notifiedReason string
	var wg sync.WaitGroup
	wg.Add(1)

	g.SetAutoFreezeNotifier(func(email, reason string) {
		notifiedEmail = email
		notifiedReason = reason
		wg.Done()
	})

	// Set low limits with auto-freeze enabled
	g.mu.Lock()
	g.limits["notifier@test.com"] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(1000),
		AutoFreezeOnLimitHit: true,
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: "notifier@test.com", ToolName: "place_order",
		Quantity: 10, Price: domain.NewINR(200), OrderType: "LIMIT",
	}

	// Trigger 3 rejections to auto-freeze
	g.CheckOrder(overLimitReq)
	g.CheckOrder(overLimitReq)
	g.CheckOrder(overLimitReq)

	// Wait for the async notifier
	wg.Wait()

	assert.Equal(t, "notifier@test.com", notifiedEmail)
	assert.Contains(t, notifiedReason, "Automatic safety freeze")
}

// =============================================================================
// checkKillSwitch: frozen with empty reason
// =============================================================================

func TestCheckKillSwitch_EmptyReason(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	// Freeze without a reason
	g.mu.Lock()
	g.limits["noreason@test.com"] = &UserLimits{
		TradingFrozen: true,
		FrozenBy:      "admin",
		FrozenReason:  "", // empty reason
	}
	g.mu.Unlock()

	r := g.CheckOrder(OrderCheckRequest{
		Email: "noreason@test.com", ToolName: "place_order",
	})
	assert.False(t, r.Allowed)
	assert.Equal(t, ReasonTradingFrozen, r.Reason)
	assert.Contains(t, r.Message, "no reason given")
}

// =============================================================================
// checkAutoFreeze: already frozen user should not be re-frozen
// =============================================================================

func TestCheckAutoFreeze_AlreadyFrozenNotRefrozen(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "alreadyfrozen@test.com"

	// Already frozen AND auto-freeze enabled
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(1000),
		AutoFreezeOnLimitHit: true,
		TradingFrozen:        true,
		FrozenBy:             "admin",
		FrozenReason:         "manual freeze",
	}
	// Inject 5 recent rejections (above threshold)
	g.trackers[email] = &UserTracker{
		DayResetAt:       time.Now(),
		RecentRejections: []time.Time{time.Now(), time.Now(), time.Now(), time.Now(), time.Now()},
	}
	g.mu.Unlock()

	// checkAutoFreeze should return false (already frozen)
	frozen := g.checkAutoFreeze(email)
	assert.False(t, frozen, "should not re-freeze an already frozen user")

	// Frozen reason should remain "manual freeze"
	limits := g.GetEffectiveLimits(email)
	assert.Equal(t, "manual freeze", limits.FrozenReason)
}

// =============================================================================
// Middleware: full coverage
// =============================================================================

func TestMiddleware_NonOrderToolPassesThrough(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	mw := Middleware(g)

	called := false
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		called = true
		return gomcp.NewToolResultText("ok"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings" // not an order tool
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, called)
	assert.NotNil(t, result)
}

func TestMiddleware_NoEmailPassesThrough(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	mw := Middleware(g)

	called := false
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		called = true
		return gomcp.NewToolResultText("ok"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order" // order tool, but no email in context
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, called, "should pass through when no email in context")
	assert.NotNil(t, result)
}

func TestMiddleware_BlockedOrder(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	g.Freeze("blocked@test.com", "admin", "test block")
	mw := Middleware(g)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		t.Error("handler should not be called for blocked order")
		return nil, nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(1500),
		"order_type":       "LIMIT",
	}

	ctx := oauth.ContextWithEmail(context.Background(), "blocked@test.com")
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestMiddleware_AllowedOrderRecordsSuccess(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	mw := Middleware(g)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("order placed"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	// confirm=true needed because the Free-tier default now requires explicit
	// acknowledgement to satisfy the RequireConfirmAllOrders gate.
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(5),
		"price":            float64(1500),
		"order_type":       "LIMIT",
		"confirm":          true,
	}

	ctx := oauth.ContextWithEmail(context.Background(), "trader@test.com")
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	// Verify order was recorded
	status := g.GetUserStatus("trader@test.com")
	assert.Equal(t, 1, status.DailyOrderCount)
}

func TestMiddleware_TriggerPriceFallback(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	mw := Middleware(g)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("sl order placed"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(5),
		"price":            float64(0), // zero price
		"trigger_price":    float64(1480),
		"order_type":       "SL",
		"confirm":          true,
	}

	ctx := oauth.ContextWithEmail(context.Background(), "sl@test.com")
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError)
}

func TestMiddleware_ErrorResponseNotRecorded(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	mw := Middleware(g)

	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("kite API error"), nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(1),
		"price":            float64(100),
		"order_type":       "LIMIT",
	}

	ctx := oauth.ContextWithEmail(context.Background(), "erruser@test.com")
	_, err := handler(ctx, req)
	require.NoError(t, err)

	// Verify order was NOT recorded since response was an error
	status := g.GetUserStatus("erruser@test.com")
	assert.Equal(t, 0, status.DailyOrderCount)
}

// =============================================================================
// safeString, safeInt, safeFloat helpers
// =============================================================================

func TestSafeString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "hello", safeString("hello"))
	assert.Equal(t, "", safeString(nil))
	assert.Equal(t, "", safeString(123))
	assert.Equal(t, "", safeString(true))
}

func TestSafeInt(t *testing.T) {
	t.Parallel()
	// MCP sends numbers as float64 from JSON
	assert.Equal(t, 10, safeInt(float64(10)))
	assert.Equal(t, 42, safeInt(42))
	assert.Equal(t, 0, safeInt(nil))
	assert.Equal(t, 0, safeInt("not a number"))
}

func TestSafeFloat(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 1500.50, safeFloat(1500.50))
	assert.Equal(t, 0.0, safeFloat(nil))
	assert.Equal(t, 0.0, safeFloat("not a number"))
	assert.Equal(t, 0.0, safeFloat(42)) // int is not float64
}

// =============================================================================
// persistLimits error path (with logger)
// =============================================================================

func TestPersistLimits_NoDBIsNoop(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	// No DB set, persist should be a no-op
	g.Freeze("nodb@test.com", "admin", "test")
	// Should not panic
	assert.True(t, g.IsFrozen("nodb@test.com"))
}

func TestPersistLimits_WithDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Freeze with DB backing
	g.Freeze("persist@test.com", "admin", "test persist")
	assert.True(t, g.IsFrozen("persist@test.com"))

	// Reload from DB
	g2 := NewGuard(logger)
	g2.SetDB(db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())
	assert.True(t, g2.IsFrozen("persist@test.com"))

	limits := g2.GetEffectiveLimits("persist@test.com")
	assert.Equal(t, "admin", limits.FrozenBy)
	assert.Equal(t, "test persist", limits.FrozenReason)
	assert.False(t, limits.FrozenAt.IsZero())
}

// =============================================================================
// InitTable: nil DB returns nil
// =============================================================================

func TestInitTable_NilDB(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	err := g.InitTable()
	assert.NoError(t, err)
}

// =============================================================================
// LoadLimits: nil DB returns nil, various DB states
// =============================================================================

func TestLoadLimits_NilDB(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	err := g.LoadLimits()
	assert.NoError(t, err)
}

func TestLoadLimits_EmptyDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	err = g.LoadLimits()
	assert.NoError(t, err)
}

func TestLoadLimits_WithFrozenAtEmpty(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Insert a row with empty frozen_at (include the new
	// require_confirm_all_orders column — set to 1 to match Free-tier default).
	err = db.ExecInsert(
		`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"empty@test.com", 50000, 20, 10, 30, 200000, 1, 1, 0, "", "", "", time.Now().Format(time.RFC3339),
	)
	require.NoError(t, err)

	err = g.LoadLimits()
	assert.NoError(t, err)

	limits := g.GetEffectiveLimits("empty@test.com")
	assert.True(t, limits.FrozenAt.IsZero())
	assert.False(t, limits.TradingFrozen)
}

func TestLoadLimits_WithFrozenAtSet(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	frozenAt := time.Now().Format(time.RFC3339)
	err = db.ExecInsert(
		`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"frozen@test.com", 50000, 20, 10, 30, 200000, 1, 1, 1, frozenAt, "admin", "test", time.Now().Format(time.RFC3339),
	)
	require.NoError(t, err)

	err = g.LoadLimits()
	assert.NoError(t, err)

	assert.True(t, g.IsFrozen("frozen@test.com"))
	limits := g.GetEffectiveLimits("frozen@test.com")
	assert.False(t, limits.FrozenAt.IsZero())
}

// =============================================================================
// maybeResetDay: test that daily counters reset after 9:15 AM IST
// =============================================================================

func TestMaybeResetDay_CrossesBoundary(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	email := "resetday@test.com"

	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	// Set DayResetAt to 2 days before the pinned clock so reset fires.
	// Using markerTimeOnPinnedDay keeps the date-component aligned with
	// g.clock() on weekend CI runs (where the pin rolls back to Friday).
	tracker.DayResetAt = markerTimeOnPinnedDay(10, 30).AddDate(0, 0, -2)
	tracker.DailyOrderCount = 150
	tracker.DailyPlacedValue = 500000
	g.mu.Unlock()

	// CheckOrder will call maybeResetDay internally
	r := g.CheckOrder(OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
		Confirmed: true,
	})
	assert.True(t, r.Allowed)

	// Verify counters were reset
	status := g.GetUserStatus(email)
	assert.Equal(t, 0, status.DailyOrderCount)
	assert.Equal(t, 0.0, status.DailyPlacedValue)
}

func TestMaybeResetDay_SameDay_NoReset(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "sameday@test.com"

	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Now() // just reset
	tracker.DailyOrderCount = 50
	g.mu.Unlock()

	// The daily count should remain
	status := g.GetUserStatus(email)
	assert.Equal(t, 50, status.DailyOrderCount)
}

// =============================================================================
// GetEffectiveLimits: all zero-fill paths
// =============================================================================

func TestGetEffectiveLimits_AllZerosFilled(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	g.mu.Lock()
	g.limits["allzero@test.com"] = &UserLimits{} // all zeros
	g.mu.Unlock()

	limits := g.GetEffectiveLimits("allzero@test.com")
	assert.Equal(t, SystemDefaults.MaxSingleOrderINR, limits.MaxSingleOrderINR)
	assert.Equal(t, SystemDefaults.MaxOrdersPerDay, limits.MaxOrdersPerDay)
	assert.Equal(t, SystemDefaults.MaxOrdersPerMinute, limits.MaxOrdersPerMinute)
	assert.Equal(t, SystemDefaults.DuplicateWindowSecs, limits.DuplicateWindowSecs)
	assert.Equal(t, SystemDefaults.MaxDailyValueINR, limits.MaxDailyValueINR)
}

// =============================================================================
// checkDuplicateOrder: disabled duplicate window (DuplicateWindowSecs <= 0)
// =============================================================================

func TestCheckDuplicateOrder_DisabledWindow(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	email := "nodup@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		DuplicateWindowSecs: -1,                          // disabled (negative bypasses the fill-from-defaults)
		MaxSingleOrderINR:   domain.NewINR(10000000),     // high limit to not interfere
		MaxDailyValueINR:    domain.NewINR(100000000),
	}
	g.mu.Unlock()

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 10,
		Price: domain.NewINR(100), OrderType: "LIMIT",
	}

	// Place and record
	r := g.CheckOrder(req)
	assert.True(t, r.Allowed)
	g.RecordOrder(email, req)

	// Same order should pass (duplicate detection disabled)
	r = g.CheckOrder(req)
	assert.True(t, r.Allowed)
}

// =============================================================================
// RecordOrder: without request params (no-arg variant)
// =============================================================================

func TestRecordOrder_WithoutParams(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "noparams@test.com"

	g.RecordOrder(email) // no OrderCheckRequest arg
	g.RecordOrder(email)

	g.mu.RLock()
	tracker := g.trackers[email]
	assert.Equal(t, 2, tracker.DailyOrderCount)
	assert.Equal(t, 2, len(tracker.RecentOrders))
	assert.Equal(t, 0, len(tracker.RecentParams)) // no params recorded
	assert.Equal(t, 0.0, tracker.DailyPlacedValue) // no value tracked
	g.mu.RUnlock()
}

// =============================================================================
// GetUserStatus: with frozen user
// =============================================================================

func TestGetUserStatus_FrozenUser(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "statusfrozen@test.com"

	g.Freeze(email, "admin", "status test")

	// Record some orders
	g.RecordOrder(email, OrderCheckRequest{
		Email: email, Quantity: 10, Price: domain.NewINR(1000),
	})

	status := g.GetUserStatus(email)
	assert.True(t, status.IsFrozen)
	assert.Equal(t, "admin", status.FrozenBy)
	assert.Equal(t, "status test", status.FrozenReason)
	assert.False(t, status.FrozenAt.IsZero())
	assert.Equal(t, 1, status.DailyOrderCount)
	assert.InDelta(t, 10000.0, status.DailyPlacedValue, 0.01)
}

// =============================================================================
// checkQuantityLimit: no freeze lookup set (fail open)
// =============================================================================

func TestCheckQuantityLimit_NoLookup(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	// No SetFreezeQuantityLookup called => nil

	// Use price=0 (MARKET) to skip order value check
	r := g.CheckOrder(OrderCheckRequest{
		Email: "nolookup@test.com", ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "INFY",
		Quantity: 999999, Price: domain.Money{}, OrderType: "MARKET",
		Confirmed: true,
	})
	assert.True(t, r.Allowed) // fail open
}

// =============================================================================
// checkQuantityLimit: freeze qty is 0 (fail open)
// =============================================================================

func TestCheckQuantityLimit_ZeroFreezeQty(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:ZEROFQ": 0,
	}})

	// Use price=0 (MARKET) to skip order value check
	r := g.CheckOrder(OrderCheckRequest{
		Email: "zerofq@test.com", ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "ZEROFQ",
		Quantity: 999999, Price: domain.Money{}, OrderType: "MARKET",
		Confirmed: true,
	})
	assert.True(t, r.Allowed) // freeze qty 0 => fail open
}

// =============================================================================
// checkQuantityLimit: empty exchange or tradingsymbol (fail open)
// =============================================================================

func TestCheckQuantityLimit_EmptyFields(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:INFY": 1800,
	}})

	// Empty tradingsymbol — use price=0 (MARKET) to skip order value check
	r := g.CheckOrder(OrderCheckRequest{
		Email: "empty@test.com", ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "",
		Quantity: 999999, Price: domain.Money{}, OrderType: "MARKET",
		Confirmed: true,
	})
	assert.True(t, r.Allowed) // fail open
}

// =============================================================================
// Middleware: handler type check (ensures Middleware returns proper type)
// =============================================================================

func TestMiddleware_ReturnsToolHandlerMiddleware(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	var mw server.ToolHandlerMiddleware = Middleware(g)
	assert.NotNil(t, mw)
}

// =============================================================================
// Concurrent global freeze and check
// =============================================================================

func TestGlobalFreeze_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	var wg sync.WaitGroup

	// Concurrent freezes and unfreezes
	for range 50 {
		wg.Go(func() {
			g.FreezeGlobal("admin", "test")
		})
		wg.Go(func() {
			g.UnfreezeGlobal()
		})
	}

	// Concurrent checks
	for range 50 {
		wg.Go(func() {
			g.CheckOrder(OrderCheckRequest{
				Email: "concurrent@test.com", ToolName: "place_order",
				Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
			})
		})
	}

	wg.Wait()
	// Just verify no panics or data races
}

// =============================================================================
// Auto-freeze with logger (covers the logger branch in checkAutoFreeze)
// =============================================================================

func TestAutoFreezeWithLogger(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)

	email := "logfreeze@test.com"
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

	// 3 rejections => auto-freeze (logger.Warn should be called)
	g.CheckOrder(overLimitReq)
	g.CheckOrder(overLimitReq)
	g.CheckOrder(overLimitReq)

	assert.True(t, g.IsFrozen(email))
}

// =============================================================================
// FreezeGlobal/UnfreezeGlobal with logger
// =============================================================================

func TestFreezeGlobal_WithLogger(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)

	g.FreezeGlobal("admin@test.com", "test with logger")
	assert.True(t, g.IsGloballyFrozen())

	g.UnfreezeGlobal()
	assert.False(t, g.IsGloballyFrozen())
}

// =============================================================================
// Middleware: blocked order with logger
// =============================================================================

func TestMiddleware_BlockedOrderWithLogger(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)
	g.Freeze("logblocked@test.com", "admin", "log test")

	mw := Middleware(g)
	handler := mw(func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		t.Error("should not be called")
		return nil, nil
	})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10),
		"price": float64(1500), "order_type": "LIMIT",
	}

	ctx := oauth.ContextWithEmail(context.Background(), "logblocked@test.com")
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	// The error message should contain the reason
}

// =============================================================================
// persistLimits: frozen_at not zero (covers the format branch)
// =============================================================================

func TestPersistLimits_FrozenAtFormatted(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Freeze sets FrozenAt to time.Now() internally
	g.Freeze("formatted@test.com", "admin", "format test")

	// Verify it persisted and can be loaded
	g2 := NewGuard(slog.Default())
	g2.SetDB(db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())

	limits := g2.GetEffectiveLimits("formatted@test.com")
	assert.False(t, limits.FrozenAt.IsZero())
}

// =============================================================================
// persistLimits: auto_freeze_on_limit_hit flag persistence
// =============================================================================

// =============================================================================
// CheckOrder: auto-freeze triggered by various check types
// (covers the auto-freeze append in checkQuantityLimit, checkDailyOrderCount,
// checkRateLimit, checkDailyValue branches within CheckOrder)
// =============================================================================

func TestCheckOrder_AutoFreezeOnQuantityLimit(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "qtyautofreeze@test.com"

	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:INFY": 100,
	}})

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		AutoFreezeOnLimitHit: true,
		MaxSingleOrderINR:    domain.NewINR(10000000), // high, won't interfere
		MaxDailyValueINR:     domain.NewINR(100000000),
	}
	g.mu.Unlock()

	overQtyReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 200,
		Price: domain.Money{}, OrderType: "MARKET", // price=0 to skip value check
	}

	// 3 rejections should trigger auto-freeze
	g.CheckOrder(overQtyReq)
	g.CheckOrder(overQtyReq)
	r := g.CheckOrder(overQtyReq)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email))
	assert.Contains(t, r.Message, "auto-frozen")
}

func TestCheckOrder_AutoFreezeOnDailyOrderCount(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "dailyautofreeze@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxOrdersPerDay:      1,
		AutoFreezeOnLimitHit: true,
		MaxSingleOrderINR:    domain.NewINR(10000000),
		MaxDailyValueINR:     domain.NewINR(100000000),
	}
	// Pre-populate tracker so daily count is at limit
	g.trackers[email] = &UserTracker{
		DailyOrderCount: 1,
		DayResetAt:      time.Now(),
	}
	g.mu.Unlock()

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
	}

	// 3 rejections should trigger auto-freeze
	g.CheckOrder(req)
	g.CheckOrder(req)
	r := g.CheckOrder(req)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email))
	assert.Contains(t, r.Message, "auto-frozen")
}

func TestCheckOrder_AutoFreezeOnRateLimit(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "rateautofreeze@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxOrdersPerMinute:   1,
		AutoFreezeOnLimitHit: true,
		MaxSingleOrderINR:    domain.NewINR(10000000),
		MaxDailyValueINR:     domain.NewINR(100000000),
	}
	now := time.Now()
	g.trackers[email] = &UserTracker{
		DayResetAt:   now,
		RecentOrders: []time.Time{now.Add(-10 * time.Second)}, // 1 order in the window
	}
	g.mu.Unlock()

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 1, Price: domain.NewINR(100), OrderType: "LIMIT",
	}

	// 3 rejections should trigger auto-freeze
	g.CheckOrder(req)
	g.CheckOrder(req)
	r := g.CheckOrder(req)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email))
	assert.Contains(t, r.Message, "auto-frozen")
}

func TestCheckOrder_AutoFreezeOnDuplicateOrder(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	pinClockInMarketHours(g)
	email := "dupautofreeze@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		AutoFreezeOnLimitHit: true,
		MaxSingleOrderINR:    domain.NewINR(10000000),
		MaxDailyValueINR:     domain.NewINR(100000000),
	}
	g.mu.Unlock()

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 10,
		Price: domain.NewINR(100), OrderType: "LIMIT",
	}

	// First order passes and gets recorded
	r := g.CheckOrder(req)
	assert.True(t, r.Allowed)
	g.RecordOrder(email, req)

	// 3 duplicate rejections should trigger auto-freeze
	g.CheckOrder(req)
	g.CheckOrder(req)
	r = g.CheckOrder(req)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email))
	assert.Contains(t, r.Message, "auto-frozen")
}

func TestCheckOrder_AutoFreezeOnDailyValue(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "valautofreeze@test.com"

	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxDailyValueINR:     domain.NewINR(1000), // very low
		AutoFreezeOnLimitHit: true,
		MaxSingleOrderINR:    domain.NewINR(10000000),
		DuplicateWindowSecs:  -1, // disable duplicate
	}
	g.trackers[email] = &UserTracker{
		DayResetAt:       time.Now(),
		DailyPlacedValue: 999, // just under limit
	}
	g.mu.Unlock()

	req := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "INFY",
		TransactionType: "BUY", Quantity: 1,
		Price: domain.NewINR(100), OrderType: "LIMIT", // value=100, total=1099 > 1000
	}

	// 3 rejections should trigger auto-freeze
	g.CheckOrder(req)
	g.CheckOrder(req)
	r := g.CheckOrder(req)
	assert.False(t, r.Allowed)
	assert.True(t, g.IsFrozen(email))
	assert.Contains(t, r.Message, "auto-frozen")
}

// =============================================================================
// maybeResetDay: verifies reset boundary at 9:15 AM IST
// =============================================================================

func TestMaybeResetDay_RecentResetNoChange(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "recentreset@test.com"

	// Set DayResetAt to right now — nothing should reset
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Now()
	tracker.DailyOrderCount = 42
	tracker.DailyPlacedValue = 50000
	g.mu.Unlock()

	status := g.GetUserStatus(email)
	assert.Equal(t, 42, status.DailyOrderCount)
	assert.InDelta(t, 50000.0, status.DailyPlacedValue, 0.01)
}

func TestMaybeResetDay_OldResetTriggersReset(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "oldreset@test.com"

	ist, _ := time.LoadLocation("Asia/Kolkata")
	// Set DayResetAt to 3 days ago — should reset
	g.mu.Lock()
	tracker := g.getOrCreateTracker(email)
	tracker.DayResetAt = time.Now().In(ist).AddDate(0, 0, -3)
	tracker.DailyOrderCount = 150
	tracker.DailyPlacedValue = 999999
	g.mu.Unlock()

	status := g.GetUserStatus(email)
	assert.Equal(t, 0, status.DailyOrderCount)
	assert.InDelta(t, 0.0, status.DailyPlacedValue, 0.01)
}

// =============================================================================
// InitTable: runs migration queries (DDL branches)
// =============================================================================

func TestInitTable_RunsMigrations(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)

	// First call creates table + runs migrations
	err = g.InitTable()
	assert.NoError(t, err)

	// Second call should be idempotent (migrations will fail with "duplicate column" but get ignored)
	err = g.InitTable()
	assert.NoError(t, err)
}

// =============================================================================
// LoadLimits: rows.Err() path (hard to trigger without mocking, but ensure full scan)
// =============================================================================

func TestLoadLimits_MultipleRows(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Insert multiple rows with different states
	for i, email := range []string{"a@test.com", "b@test.com", "c@test.com"} {
		frozenAt := ""
		frozen := 0
		if i == 1 {
			frozen = 1
			frozenAt = time.Now().Format(time.RFC3339)
		}
		err = db.ExecInsert(
			`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			email, 50000, 20, 10, 30, 200000, 1, 1, frozen, frozenAt, "", "", time.Now().Format(time.RFC3339),
		)
		require.NoError(t, err)
	}

	err = g.LoadLimits()
	assert.NoError(t, err)

	assert.False(t, g.IsFrozen("a@test.com"))
	assert.True(t, g.IsFrozen("b@test.com"))
	assert.False(t, g.IsFrozen("c@test.com"))
}

// =============================================================================
// persistLimits: error path (closed DB triggers error logging)
// =============================================================================

func TestPersistLimits_DBError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	g := NewGuard(logger)
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Close the DB to trigger write errors
	db.Close()

	// Freeze should still update in-memory state, but persist will fail (logged, not panicked)
	g.Freeze("dberr@test.com", "admin", "error test")
	assert.True(t, g.IsFrozen("dberr@test.com"))
}

// =============================================================================
// InitTable: DDL error path (closed DB)
// =============================================================================

func TestInitTable_DDLError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	g := NewGuard(slog.Default())
	g.SetDB(db)

	// Close DB before InitTable to trigger DDL error
	db.Close()

	err = g.InitTable()
	assert.Error(t, err)
}

// =============================================================================
// LoadLimits: error paths (closed DB)
// =============================================================================

func TestLoadLimits_QueryError(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Close DB before LoadLimits to trigger query error
	db.Close()

	err = g.LoadLimits()
	assert.Error(t, err)
}

func TestPersistLimits_AutoFreezeFlag(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	g := NewGuard(slog.Default())
	g.SetDB(db)
	require.NoError(t, g.InitTable())

	// Set limits with auto-freeze disabled, then persist
	g.mu.Lock()
	g.limits["autotest@test.com"] = &UserLimits{
		MaxSingleOrderINR:    domain.NewINR(200000),
		AutoFreezeOnLimitHit: false,
	}
	g.persistLimits("autotest@test.com", g.limits["autotest@test.com"])
	g.mu.Unlock()

	// Reload and verify
	g2 := NewGuard(slog.Default())
	g2.SetDB(db)
	require.NoError(t, g2.InitTable())
	require.NoError(t, g2.LoadLimits())

	limits := g2.GetEffectiveLimits("autotest@test.com")
	assert.False(t, limits.AutoFreezeOnLimitHit)
}
