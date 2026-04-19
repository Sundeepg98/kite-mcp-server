package riskguard

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGuard() *Guard {
	return NewGuard(slog.Default())
}

func TestCheckKillSwitch(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	t.Run("unfrozen user passes", func(t *testing.T) {
		// Confirmed=true bypasses the new default-on require-confirm gate so
		// this test isolates the kill-switch behaviour.
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order", Confirmed: true})
		assert.True(t, r.Allowed)
	})

	t.Run("frozen user blocked", func(t *testing.T) {
		g.Freeze("user@test.com", "admin@test.com", "testing")
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order", Confirmed: true})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonTradingFrozen, r.Reason)
		assert.Contains(t, r.Message, "testing")
	})

	t.Run("unfreeze restores access", func(t *testing.T) {
		g.Unfreeze("user@test.com")
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order", Confirmed: true})
		assert.True(t, r.Allowed)
	})
}

func TestCheckOrderValue(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	// Tightened Free-tier default: Rs 50,000 per order. Tests updated to reflect
	// the new cap. Confirmed=true bypasses the new default-on require-confirm
	// gate so these tests isolate the value-check behaviour.
	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 10, Price: 1000, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.True(t, r.Allowed) // 10*1000=10000 < 50000
	})

	t.Run("over limit blocked", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 10, Price: 10000, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.False(t, r.Allowed) // 10*10000=100000 > 50000
		assert.Equal(t, ReasonOrderValue, r.Reason)
	})

	t.Run("MARKET order skipped (price 0)", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 100000, Price: 0, OrderType: "MARKET",
			Confirmed: true,
		})
		assert.True(t, r.Allowed)
	})
}

type mockFreezeQty struct {
	data map[string]uint32
}

func (m *mockFreezeQty) GetFreezeQuantity(exchange, symbol string) (uint32, bool) {
	v, ok := m.data[exchange+":"+symbol]
	return v, ok
}

func TestCheckQuantityLimit(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:RELIANCE": 1800,
		"NFO:NIFTY":    1800,
	}})

	t.Run("under freeze qty passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 100,
			Confirmed: true,
		})
		assert.True(t, r.Allowed)
	})

	t.Run("over freeze qty blocked", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 2000,
			Confirmed: true,
		})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonQuantityLimit, r.Reason)
	})

	t.Run("unknown instrument passes (fail open)", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "UNKNOWN", Quantity: 999999,
			Confirmed: true,
		})
		assert.True(t, r.Allowed)
	})
}

func TestCheckDailyOrderCount(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{Email: "u@t.com", ToolName: "place_order", Confirmed: true})
		assert.True(t, r.Allowed)
	})

	t.Run("at limit blocked", func(t *testing.T) {
		// Set a low limit for testing
		g.mu.Lock()
		g.limits["u@t.com"] = &UserLimits{MaxOrdersPerDay: 3}
		g.trackers["u@t.com"] = &UserTracker{DailyOrderCount: 3, DayResetAt: time.Now()}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{Email: "u@t.com", ToolName: "place_order", Confirmed: true})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonDailyOrderLimit, r.Reason)
	})
}

func TestRecordOrder(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	g.RecordOrder("u@t.com")
	g.RecordOrder("u@t.com")

	g.mu.RLock()
	count := g.trackers["u@t.com"].DailyOrderCount
	g.mu.RUnlock()

	assert.Equal(t, 2, count)
}

func TestIsOrderTool(t *testing.T) {
	t.Parallel()
	assert.True(t, IsOrderTool("place_order"))
	assert.True(t, IsOrderTool("modify_order"))
	assert.True(t, IsOrderTool("close_all_positions"))
	assert.False(t, IsOrderTool("cancel_order"))
	assert.False(t, IsOrderTool("get_holdings"))
}

func TestGetEffectiveLimits(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	t.Run("returns system defaults for unknown user", func(t *testing.T) {
		l := g.GetEffectiveLimits("unknown@test.com")
		assert.Equal(t, SystemDefaults.MaxSingleOrderINR, l.MaxSingleOrderINR)
		assert.Equal(t, SystemDefaults.MaxOrdersPerDay, l.MaxOrdersPerDay)
	})

	t.Run("returns per-user override", func(t *testing.T) {
		g.mu.Lock()
		g.limits["custom@test.com"] = &UserLimits{MaxSingleOrderINR: 100000, MaxOrdersPerDay: 50}
		g.mu.Unlock()

		l := g.GetEffectiveLimits("custom@test.com")
		assert.Equal(t, float64(100000), l.MaxSingleOrderINR)
		assert.Equal(t, 50, l.MaxOrdersPerDay)
	})

	t.Run("fills zero values from defaults", func(t *testing.T) {
		g.mu.Lock()
		g.limits["partial@test.com"] = &UserLimits{MaxSingleOrderINR: 100000} // MaxOrdersPerDay=0
		g.mu.Unlock()

		l := g.GetEffectiveLimits("partial@test.com")
		assert.Equal(t, float64(100000), l.MaxSingleOrderINR)
		assert.Equal(t, SystemDefaults.MaxOrdersPerDay, l.MaxOrdersPerDay) // filled from default
	})
}

func TestCheckRateLimit(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "rate@test.com"

	// Set a low per-minute limit for testing
	g.mu.Lock()
	g.limits[email] = &UserLimits{MaxOrdersPerMinute: 3}
	g.mu.Unlock()

	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{Email: email, ToolName: "place_order", Confirmed: true})
		assert.True(t, r.Allowed)
	})

	t.Run("at limit blocked", func(t *testing.T) {
		// Record 3 orders in the last minute
		g.mu.Lock()
		now := time.Now()
		tracker := g.getOrCreateTracker(email)
		tracker.RecentOrders = []time.Time{
			now.Add(-30 * time.Second),
			now.Add(-20 * time.Second),
			now.Add(-10 * time.Second),
		}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{Email: email, ToolName: "place_order", Confirmed: true})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonRateLimit, r.Reason)
		assert.Contains(t, r.Message, "limit: 3")
	})

	t.Run("old orders pruned — passes again", func(t *testing.T) {
		g.mu.Lock()
		tracker := g.getOrCreateTracker(email)
		tracker.RecentOrders = []time.Time{
			time.Now().Add(-90 * time.Second), // older than 60s
			time.Now().Add(-80 * time.Second),
			time.Now().Add(-70 * time.Second),
		}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{Email: email, ToolName: "place_order", Confirmed: true})
		assert.True(t, r.Allowed)
	})
}

func TestCheckDuplicate(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "dup@test.com"

	baseReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Exchange: "NSE", Tradingsymbol: "RELIANCE", TransactionType: "BUY", Quantity: 10,
		Price: 2500, OrderType: "LIMIT", Confirmed: true,
	}

	t.Run("first order passes", func(t *testing.T) {
		r := g.CheckOrder(baseReq)
		assert.True(t, r.Allowed)
		// Record it
		g.RecordOrder(email, baseReq)
	})

	t.Run("same order within window blocked", func(t *testing.T) {
		r := g.CheckOrder(baseReq)
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonDuplicateOrder, r.Reason)
		assert.Contains(t, r.Message, "BUY NSE RELIANCE qty 10")
	})

	t.Run("different quantity passes", func(t *testing.T) {
		diffReq := baseReq
		diffReq.Quantity = 20
		r := g.CheckOrder(diffReq)
		assert.True(t, r.Allowed)
	})

	t.Run("different transaction type passes", func(t *testing.T) {
		diffReq := baseReq
		diffReq.TransactionType = "SELL"
		r := g.CheckOrder(diffReq)
		assert.True(t, r.Allowed)
	})

	t.Run("after window expires passes", func(t *testing.T) {
		// Move all recorded orders back beyond the 30s window
		g.mu.Lock()
		tracker := g.getOrCreateTracker(email)
		for i := range tracker.RecentParams {
			tracker.RecentParams[i].PlacedAt = time.Now().Add(-60 * time.Second)
		}
		g.mu.Unlock()

		r := g.CheckOrder(baseReq)
		assert.True(t, r.Allowed)
	})
}

func TestCheckDailyValue(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "value@test.com"

	// Set a low daily value limit for testing
	g.mu.Lock()
	g.limits[email] = &UserLimits{MaxDailyValueINR: 100000} // Rs 1,00,000
	g.mu.Unlock()

	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 10, Price: 1000, OrderType: "LIMIT",
		})
		assert.True(t, r.Allowed) // 10*1000 = 10000 < 100000
	})

	t.Run("cumulative over limit blocked", func(t *testing.T) {
		// Record orders worth Rs 90,000
		g.mu.Lock()
		tracker := g.getOrCreateTracker(email)
		tracker.DailyPlacedValue = 90000
		tracker.DayResetAt = time.Now()
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 10, Price: 1500, OrderType: "LIMIT", // 15000, total would be 105000
		})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonDailyValueLimit, r.Reason)
		assert.Contains(t, r.Message, "exceeds daily limit")
	})

	t.Run("MARKET order skipped (price 0)", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 10000, Price: 0, OrderType: "MARKET",
		})
		assert.True(t, r.Allowed)
	})

	t.Run("reset at 9:15 clears daily value", func(t *testing.T) {
		g.mu.Lock()
		tracker := g.getOrCreateTracker(email)
		// Set the last reset to well before today's 9:15 AM
		ist, _ := time.LoadLocation("Asia/Kolkata")
		tracker.DayResetAt = time.Now().In(ist).AddDate(0, 0, -1)
		tracker.DailyPlacedValue = 99999
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 10, Price: 1000, OrderType: "LIMIT",
		})
		assert.True(t, r.Allowed) // daily value was reset
	})
}

func TestFreezeUnfreeze(t *testing.T) {
	t.Parallel()
	g := newTestGuard()

	require.False(t, g.IsFrozen("user@test.com"))

	g.Freeze("user@test.com", "admin", "risk breach")
	require.True(t, g.IsFrozen("user@test.com"))

	g.Unfreeze("user@test.com")
	require.False(t, g.IsFrozen("user@test.com"))
}

func TestAutoFreeze(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "autofreeze@test.com"

	// Set a very low single order limit to easily trigger rejections.
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    1000, // Rs 1,000
		AutoFreezeOnLimitHit: true,
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 10, Price: 200, OrderType: "LIMIT", // 10*200=2000 > 1000
	}

	t.Run("first two rejections do not freeze", func(t *testing.T) {
		r := g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonOrderValue, r.Reason)
		assert.False(t, g.IsFrozen(email))

		r = g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.False(t, g.IsFrozen(email))
	})

	t.Run("third rejection triggers auto-freeze", func(t *testing.T) {
		r := g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.True(t, g.IsFrozen(email))
		assert.Contains(t, r.Message, "auto-frozen due to repeated violations")

		// Verify freeze metadata
		limits := g.GetEffectiveLimits(email)
		assert.Equal(t, "riskguard:circuit-breaker", limits.FrozenBy)
		assert.Equal(t, "Automatic safety freeze: repeated limit violations", limits.FrozenReason)
	})

	t.Run("subsequent orders blocked by kill switch", func(t *testing.T) {
		r := g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonTradingFrozen, r.Reason)
	})

	t.Run("unfreeze restores access", func(t *testing.T) {
		g.Unfreeze(email)
		assert.False(t, g.IsFrozen(email))

		// An under-limit order should pass now
		underLimitReq := OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 1, Price: 100, OrderType: "LIMIT", // 100 < 1000
		}
		r := g.CheckOrder(underLimitReq)
		assert.True(t, r.Allowed)
	})

	t.Run("old rejections outside window do not count", func(t *testing.T) {
		// Unfreeze and clear rejections, then add old ones
		g.Unfreeze(email)
		g.mu.Lock()
		tracker := g.getOrCreateTracker(email)
		tracker.RecentRejections = []time.Time{
			time.Now().Add(-10 * time.Minute), // well outside 5-minute window
			time.Now().Add(-8 * time.Minute),
		}
		g.mu.Unlock()

		// One new rejection should NOT trigger freeze (only 1 in window, 2 outside)
		r := g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.False(t, g.IsFrozen(email))
	})
}

func TestAutoFreezeDisabled(t *testing.T) {
	t.Parallel()
	g := newTestGuard()
	email := "noautofreeze@test.com"

	// Explicitly disable auto-freeze
	g.mu.Lock()
	g.limits[email] = &UserLimits{
		MaxSingleOrderINR:    1000,
		AutoFreezeOnLimitHit: false,
	}
	g.mu.Unlock()

	overLimitReq := OrderCheckRequest{
		Email: email, ToolName: "place_order",
		Quantity: 10, Price: 200, OrderType: "LIMIT", // 2000 > 1000
	}

	// Trigger 5 rejections — none should cause auto-freeze
	for i := 0; i < 5; i++ {
		r := g.CheckOrder(overLimitReq)
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonOrderValue, r.Reason)
		assert.NotContains(t, r.Message, "auto-frozen")
	}

	assert.False(t, g.IsFrozen(email), "user should NOT be frozen when AutoFreezeOnLimitHit is false")
}
