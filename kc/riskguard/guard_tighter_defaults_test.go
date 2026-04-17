// Tests for tightened Free-tier defaults introduced to mitigate the
// "prompt-injection / market-manipulation via sub-cap orders" landmine.
//
// Scenario: an adversarial prompt injects 10x Rs 49,999 buy orders which are
// each below the previous Rs 5,00,000 cap but whose cumulative notional
// (~Rs 5,00,000) looks like manipulative layering to SEBI surveillance —
// leaving Sundeep liable as beneficial owner.
//
// Mitigation: lower defaults so that
//   - per-order cap is Rs 50,000 (one layering order still blocked)
//   - daily notional is Rs 2,00,000 (4 layering orders max)
//   - daily count is 20 (reasonable retail ceiling)
// plus a default-on "require confirmation for every order" switch so that
// silent auto-execution by an agent is impossible without a user ACK.
package riskguard

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTightenedSystemDefaults asserts the new Free-tier default values.
// These numbers are the security-critical contract. If a future change
// needs different numbers, update the defaults AND this test in the same
// commit so the intent is explicit.
func TestTightenedSystemDefaults(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"per-order cap Rs 50,000", SystemDefaults.MaxSingleOrderINR, float64(50000)},
		{"daily order count 20", SystemDefaults.MaxOrdersPerDay, 20},
		{"daily notional Rs 2,00,000", SystemDefaults.MaxDailyValueINR, float64(200000)},
		{"require-confirm-all-orders default ON", SystemDefaults.RequireConfirmAllOrders, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got, "tightened default changed unexpectedly")
		})
	}
}

// TestTightenedDefaults_EnforcedAtRuntime verifies that the new numbers are
// actually applied by CheckOrder (not just stored in the SystemDefaults struct).
// Uses an unconfigured user (no per-user override) so the engine falls back to
// SystemDefaults.
func TestTightenedDefaults_EnforcedAtRuntime(t *testing.T) {
	// Order-value cap: Rs 50,000 — an order of Rs 49,999 passes value check,
	// an order of Rs 50,001 fails.
	t.Run("per-order cap Rs 50,000 enforces", func(t *testing.T) {
		g := newTestGuard()
		// Disable confirm-all for this focused test — we're asserting the
		// value limit specifically.
		g.mu.Lock()
		g.limits["valtest@t.com"] = &UserLimits{RequireConfirmAllOrders: false}
		g.mu.Unlock()

		// 1 x Rs 49,999 — under the 50k cap
		r := g.CheckOrder(OrderCheckRequest{
			Email: "valtest@t.com", ToolName: "place_order",
			Quantity: 1, Price: 49999, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.True(t, r.Allowed, "Rs 49,999 should pass the new Rs 50k cap")

		// 1 x Rs 50,001 — over the cap
		r = g.CheckOrder(OrderCheckRequest{
			Email: "valtest@t.com", ToolName: "place_order",
			Quantity: 1, Price: 50001, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.False(t, r.Allowed, "Rs 50,001 should be blocked by the new Rs 50k cap")
		assert.Equal(t, ReasonOrderValue, r.Reason)
	})

	// Daily count: 20 orders/day.
	t.Run("daily count 20 enforces", func(t *testing.T) {
		g := newTestGuard()
		email := "countcap@t.com"
		g.mu.Lock()
		// Pre-populate so tracker says user has placed 20 today.
		tr := g.getOrCreateTracker(email)
		tr.DailyOrderCount = 20
		// Disable confirm-all + auto-freeze + duplicate checks so this test
		// cleanly isolates the daily-count branch.
		g.limits[email] = &UserLimits{
			RequireConfirmAllOrders: false,
			AutoFreezeOnLimitHit:    false,
			DuplicateWindowSecs:     -1,
		}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Quantity: 1, Price: 100, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.False(t, r.Allowed, "21st order in a day should be blocked at count 20 default")
		assert.Equal(t, ReasonDailyOrderLimit, r.Reason)
		assert.Contains(t, r.Message, "20", "error message should mention the limit")
	})

	// Daily notional: Rs 2,00,000.
	t.Run("daily notional Rs 2,00,000 enforces", func(t *testing.T) {
		g := newTestGuard()
		email := "notional@t.com"
		g.mu.Lock()
		tr := g.getOrCreateTracker(email)
		tr.DailyPlacedValue = 199000 // Rs 1,99,000 already placed
		g.limits[email] = &UserLimits{
			RequireConfirmAllOrders: false,
			AutoFreezeOnLimitHit:    false,
			DuplicateWindowSecs:     -1,
		}
		g.mu.Unlock()

		// Rs 2,000 order => total Rs 2,01,000 > Rs 2,00,000 cap → blocked
		r := g.CheckOrder(OrderCheckRequest{
			Email: email, ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "X",
			TransactionType: "BUY",
			Quantity:        2, Price: 1000, OrderType: "LIMIT",
			Confirmed: true,
		})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonDailyValueLimit, r.Reason)
	})
}

// TestRequireConfirmAllOrders verifies that, with default-on confirmation,
// a brand-new user's orders are blocked until they supply Confirmed=true.
// This is the security-critical check against silent prompt-injection
// auto-execution.
func TestRequireConfirmAllOrders(t *testing.T) {
	t.Run("fresh guard: unconfirmed order blocked", func(t *testing.T) {
		g := newTestGuard()
		// No per-user override — pure SystemDefaults path.
		r := g.CheckOrder(OrderCheckRequest{
			Email: "fresh@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "INFY",
			TransactionType: "BUY",
			Quantity:        1, Price: 100, OrderType: "LIMIT",
			// Confirmed: false (default)
		})
		assert.False(t, r.Allowed, "unconfirmed order should be blocked by default")
		assert.Equal(t, ReasonConfirmationRequired, r.Reason)
		assert.Contains(t, r.Message, "confirmation required")
	})

	t.Run("fresh guard: confirmed order passes", func(t *testing.T) {
		g := newTestGuard()
		r := g.CheckOrder(OrderCheckRequest{
			Email: "ack@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "INFY",
			TransactionType: "BUY",
			Quantity:        1, Price: 100, OrderType: "LIMIT",
			Confirmed:       true,
		})
		assert.True(t, r.Allowed, "explicitly confirmed under-cap order should pass")
	})

	t.Run("per-user override can disable require-confirm", func(t *testing.T) {
		g := newTestGuard()
		// Power user explicitly opts out.
		g.mu.Lock()
		g.limits["power@t.com"] = &UserLimits{
			RequireConfirmAllOrders: false,
		}
		g.mu.Unlock()

		r := g.CheckOrder(OrderCheckRequest{
			Email: "power@t.com", ToolName: "place_order",
			Exchange: "NSE", Tradingsymbol: "INFY",
			TransactionType: "BUY",
			Quantity:        1, Price: 100, OrderType: "LIMIT",
			// Confirmed: false — should still pass because user opted out
		})
		assert.True(t, r.Allowed, "user-level opt-out should bypass confirmation check")
	})

	t.Run("confirmation gate runs AFTER kill-switch (kill-switch takes priority)", func(t *testing.T) {
		g := newTestGuard()
		g.Freeze("frozen@t.com", "admin", "compliance hold")

		// Even without Confirmed=true, the response must say "frozen" not
		// "confirmation required" — otherwise an attacker could probe freeze
		// state by checking which error they get.
		r := g.CheckOrder(OrderCheckRequest{
			Email: "frozen@t.com", ToolName: "place_order",
			Quantity: 1, Price: 100, OrderType: "LIMIT",
		})
		assert.False(t, r.Allowed)
		assert.Equal(t, ReasonTradingFrozen, r.Reason, "kill-switch should block before confirmation check")
	})

	t.Run("prompt-injection scenario: 10 x Rs 49,999 orders without confirmation all blocked", func(t *testing.T) {
		// This is the exact attacker scenario from the threat model.
		g := newTestGuard()
		email := "victim@t.com"
		for i := 0; i < 10; i++ {
			r := g.CheckOrder(OrderCheckRequest{
				Email: email, ToolName: "place_order",
				Exchange: "NSE", Tradingsymbol: "TARGET",
				TransactionType: "BUY",
				Quantity:        1, Price: 49999, OrderType: "LIMIT",
				// Confirmed: false — this is the prompt-injection case
			})
			assert.False(t, r.Allowed, "layering order %d should be blocked", i+1)
			assert.Equal(t, ReasonConfirmationRequired, r.Reason,
				"sub-cap layering order %d should be blocked by confirmation gate", i+1)
		}
	})
}
