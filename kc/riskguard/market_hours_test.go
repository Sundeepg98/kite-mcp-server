// Tests for the market-hours rejection (T1 in the gap catalogue) — rejects
// any LIVE order placed outside NSE/BSE equity-cash market hours
// (weekdays, [09:15, 15:30) IST). Variety="amo" bypasses; weekends always
// reject. Holiday calendar is intentionally NOT modelled here — that is a
// Phase-2 enhancement noted in the commit message; we cover weekend +
// time-of-day only.
package riskguard

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mustIST is a tiny test helper that fails the test rather than swallowing a
// LoadLocation error — keeps each table case readable.
func mustIST(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		t.Fatalf("Asia/Kolkata tzdata missing: %v", err)
	}
	return loc
}

// TestCheckMarketHours_TableDriven covers the full decision matrix:
// weekend always rejects (regardless of time), weekday rejects outside
// [09:15, 15:30) IST, AMO variety bypasses, and the "AllowOffHours"
// per-user opt-in does NOT bypass this check (off-hours and market-hours
// are independent guards — opting into 02:00–06:00 trading should not
// silently let MARKET orders bypass the exchange-closed gate).
func TestCheckMarketHours_TableDriven(t *testing.T) {
	t.Parallel()
	ist := mustIST(t)

	tests := []struct {
		name        string
		now         time.Time
		variety     string
		allowOffHrs bool
		wantAllowed bool
		wantReason  RejectionReason
	}{
		// Weekday boundaries — Wednesday 2026-04-22 is the reference weekday.
		{
			name:        "weekday open — 10:30 IST allowed",
			now:         time.Date(2026, 4, 22, 10, 30, 0, 0, ist),
			variety:     "regular",
			wantAllowed: true,
		},
		{
			name:        "weekday at exactly 09:15 IST allowed (boundary inclusive)",
			now:         time.Date(2026, 4, 22, 9, 15, 0, 0, ist),
			variety:     "regular",
			wantAllowed: true,
		},
		{
			name:        "weekday at 09:14:59 IST rejected (just before open)",
			now:         time.Date(2026, 4, 22, 9, 14, 59, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		{
			name:        "weekday pre-open 08:00 IST rejected",
			now:         time.Date(2026, 4, 22, 8, 0, 0, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		{
			name:        "weekday at exactly 15:30 IST rejected (boundary exclusive — close)",
			now:         time.Date(2026, 4, 22, 15, 30, 0, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		{
			name:        "weekday at 15:29:59 IST allowed (just before close)",
			now:         time.Date(2026, 4, 22, 15, 29, 59, 0, ist),
			variety:     "regular",
			wantAllowed: true,
		},
		{
			name:        "weekday post-close 16:00 IST rejected",
			now:         time.Date(2026, 4, 22, 16, 0, 0, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		// Weekends — always reject regardless of time-of-day.
		{
			name:        "saturday at 10:30 IST rejected",
			now:         time.Date(2026, 4, 25, 10, 30, 0, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		{
			name:        "sunday at 12:00 IST rejected",
			now:         time.Date(2026, 4, 26, 12, 0, 0, 0, ist),
			variety:     "regular",
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
		// AMO bypass — variety=amo always allowed (Kite forwards to next
		// session anyway). Case-insensitive match because Kite accepts both.
		{
			name:        "AMO on saturday 10:30 IST allowed (bypass)",
			now:         time.Date(2026, 4, 25, 10, 30, 0, 0, ist),
			variety:     "amo",
			wantAllowed: true,
		},
		{
			name:        "AMO uppercase on sunday 23:00 IST allowed (case-insensitive)",
			now:         time.Date(2026, 4, 26, 23, 0, 0, 0, ist),
			variety:     "AMO",
			wantAllowed: true,
		},
		{
			name:        "AMO on weekday post-close allowed",
			now:         time.Date(2026, 4, 22, 18, 0, 0, 0, ist),
			variety:     "amo",
			wantAllowed: true,
		},
		// AllowOffHours opt-in does NOT bypass market-hours: a power user
		// who runs overnight automation (the 02:00–06:00 window) still
		// cannot place a LIVE order while the exchange is closed —
		// they must use AMO or wait for the open.
		{
			name:        "AllowOffHours=true does NOT bypass market-hours on saturday",
			now:         time.Date(2026, 4, 25, 10, 30, 0, 0, ist),
			variety:     "regular",
			allowOffHrs: true,
			wantAllowed: false,
			wantReason:  ReasonMarketClosed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := NewGuard(slog.Default())
			g.SetClock(func() time.Time { return tc.now })

			email := "trader@test.com"
			g.mu.Lock()
			g.limits[email] = &UserLimits{
				RequireConfirmAllOrders: false, // isolate this check
				MaxSingleOrderINR:       1_000_000,
				MaxDailyValueINR:        100_000_000,
				MaxOrdersPerDay:         1_000_000,
				MaxOrdersPerMinute:      1_000_000,
				AllowOffHours:           tc.allowOffHrs,
			}
			g.mu.Unlock()

			result := g.checkMarketHours(OrderCheckRequest{
				Email:     email,
				ToolName:  "place_order",
				Variety:   tc.variety,
				Quantity:  1,
				Price:     100,
				OrderType: "LIMIT",
				Confirmed: true,
			})
			if tc.wantAllowed {
				assert.True(t, result.Allowed, "expected allowed; got blocked: %s", result.Message)
				return
			}
			assert.False(t, result.Allowed, "expected blocked; got allowed")
			assert.Equal(t, tc.wantReason, result.Reason)
			assert.NotEmpty(t, result.Message, "rejection message must guide the user (e.g. AMO hint)")
		})
	}
}

// TestCheckMarketHours_TZDataMissing — when Asia/Kolkata cannot be loaded
// (e.g. minimal container without tzdata), the check fails open. Same
// posture as the existing checkOffHours — a deployment-config issue must
// not cause a global trading lockout.
func TestCheckMarketHours_TZDataMissing(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())
	// Inject a stub IST loader that always returns error to simulate a
	// container without tzdata. We can't actually break time.LoadLocation
	// in a unit test without a global swap, so we rely on the production
	// code path's nil-guard via marketHoursISTOverride (set to a sentinel
	// that flags "treat as missing").
	prev := marketHoursISTOverride
	marketHoursISTOverride = func() (*time.Location, error) {
		return nil, errMarketHoursTZUnavailable
	}
	t.Cleanup(func() { marketHoursISTOverride = prev })

	email := "trader@test.com"
	g.mu.Lock()
	g.limits[email] = &UserLimits{RequireConfirmAllOrders: false}
	g.mu.Unlock()

	result := g.checkMarketHours(OrderCheckRequest{
		Email:    email,
		ToolName: "place_order",
		Variety:  "regular",
	})
	assert.True(t, result.Allowed, "missing tzdata must fail OPEN — never lock everyone out")
}
