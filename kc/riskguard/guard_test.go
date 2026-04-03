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
	g := newTestGuard()

	t.Run("unfrozen user passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order"})
		assert.True(t, r.Allowed)
	})

	t.Run("frozen user blocked", func(t *testing.T) {
		g.Freeze("user@test.com", "admin@test.com", "testing")
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order"})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonTradingFrozen, r.Reason)
		assert.Contains(t, r.Message, "testing")
	})

	t.Run("unfreeze restores access", func(t *testing.T) {
		g.Unfreeze("user@test.com")
		r := g.CheckOrder(OrderCheckRequest{Email: "user@test.com", ToolName: "place_order"})
		assert.True(t, r.Allowed)
	})
}

func TestCheckOrderValue(t *testing.T) {
	g := newTestGuard()

	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 10, Price: 1000, OrderType: "LIMIT",
		})
		assert.True(t, r.Allowed) // 10*1000=10000 < 500000
	})

	t.Run("over limit blocked", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 100, Price: 10000, OrderType: "LIMIT",
		})
		assert.False(t, r.Allowed) // 100*10000=1000000 > 500000
		assert.Equal(t, ReasonOrderValue, r.Reason)
	})

	t.Run("MARKET order skipped (price 0)", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Quantity: 100000, Price: 0, OrderType: "MARKET",
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
	g := newTestGuard()
	g.SetFreezeQuantityLookup(&mockFreezeQty{data: map[string]uint32{
		"NSE:RELIANCE": 1800,
		"NFO:NIFTY":    1800,
	}})

	t.Run("under freeze qty passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 100,
		})
		assert.True(t, r.Allowed)
	})

	t.Run("over freeze qty blocked", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "RELIANCE", Quantity: 2000,
		})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonQuantityLimit, r.Reason)
	})

	t.Run("unknown instrument passes (fail open)", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{
			Email: "u@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "UNKNOWN", Quantity: 999999,
		})
		assert.True(t, r.Allowed)
	})
}

func TestCheckDailyOrderCount(t *testing.T) {
	g := newTestGuard()

	t.Run("under limit passes", func(t *testing.T) {
		r := g.CheckOrder(OrderCheckRequest{Email: "u@t.com", ToolName: "place_order"})
		assert.True(t, r.Allowed)
	})

	t.Run("at limit blocked", func(t *testing.T) {
		// Set a low limit for testing
		g.mu.Lock()
		g.limits["u@t.com"] = &UserLimits{MaxOrdersPerDay: 3}
		g.trackers["u@t.com"] = &UserTracker{DailyOrderCount: 3, DayResetAt: time.Now()}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{Email: "u@t.com", ToolName: "place_order"})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonDailyOrderLimit, r.Reason)
	})
}

func TestRecordOrder(t *testing.T) {
	g := newTestGuard()
	g.RecordOrder("u@t.com")
	g.RecordOrder("u@t.com")

	g.mu.RLock()
	count := g.trackers["u@t.com"].DailyOrderCount
	g.mu.RUnlock()

	assert.Equal(t, 2, count)
}

func TestIsOrderTool(t *testing.T) {
	assert.True(t, IsOrderTool("place_order"))
	assert.True(t, IsOrderTool("modify_order"))
	assert.True(t, IsOrderTool("close_all_positions"))
	assert.False(t, IsOrderTool("cancel_order"))
	assert.False(t, IsOrderTool("get_holdings"))
}

func TestGetEffectiveLimits(t *testing.T) {
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

func TestFreezeUnfreeze(t *testing.T) {
	g := newTestGuard()

	require.False(t, g.IsFrozen("user@test.com"))

	g.Freeze("user@test.com", "admin", "risk breach")
	require.True(t, g.IsFrozen("user@test.com"))

	g.Unfreeze("user@test.com")
	require.False(t, g.IsFrozen("user@test.com"))
}
