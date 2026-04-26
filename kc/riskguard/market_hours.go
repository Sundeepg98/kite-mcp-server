package riskguard

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// market_hours.go — T1 in the gap catalogue. Rejects any LIVE order placed
// outside NSE/BSE equity-cash market hours (weekdays, 09:15 IST inclusive
// → 15:30 IST exclusive). Variety="amo" bypasses (After-Market Orders are
// queued by Kite for the next session). Holidays are NOT modelled here —
// adding a fed-from-NSE holiday calendar is a Phase-2 enhancement; the
// Friday-of-a-public-holiday case is currently a permitted false-allow
// (Kite's own OMS will reject it). Acceptable trade-off: the cost of
// false-rejecting a real trader on a holiday is much higher than the
// cost of forwarding a doomed-anyway order to Kite once a year.

// errMarketHoursTZUnavailable is returned by the IST loader stub when a
// test wants to simulate a container without tzdata. Production callers
// never see it; the production path uses time.LoadLocation directly.
var errMarketHoursTZUnavailable = errors.New("riskguard: Asia/Kolkata tzdata unavailable")

// marketHoursISTOverride is a test seam for forcing a tzdata-missing path
// without a global mutation of time.LoadLocation. nil ⇒ use the real
// time.LoadLocation. Set in tests via t.Cleanup to restore.
var marketHoursISTOverride func() (*time.Location, error)

// loadMarketHoursIST resolves the IST timezone via the test seam if set,
// otherwise via time.LoadLocation. Centralised so the caller doesn't have
// to remember the seam exists.
func loadMarketHoursIST() (*time.Location, error) {
	if marketHoursISTOverride != nil {
		return marketHoursISTOverride()
	}
	return time.LoadLocation("Asia/Kolkata")
}

// Market-hours boundaries — NSE/BSE equity-cash session [09:15, 15:30) IST.
// Stored as minute-of-day (hour*60+min) so the comparison is one integer
// against the current IST clock, no time.Time arithmetic per call.
const (
	marketOpenIST  = 9*60 + 15  // 09:15 IST inclusive
	marketCloseIST = 15*60 + 30 // 15:30 IST exclusive
)

// isAMOVariety returns true when the order is an After-Market Order in
// Kite vocabulary. Case-insensitive because Kite accepts "amo" / "AMO".
// AMO orders are queued for the next session and therefore exempt from
// the market-hours block — the whole point of an AMO is to place it
// while the market is closed.
func isAMOVariety(variety string) bool {
	return strings.EqualFold(strings.TrimSpace(variety), "amo")
}

// checkMarketHours rejects any non-AMO order placed outside [09:15, 15:30)
// IST on a weekday. AMO bypasses unconditionally (next-session queue).
// Weekends always reject regardless of time. AllowOffHours does NOT bypass
// this check — AllowOffHours is the per-user opt-in for the 02:00–06:00
// IST hostile-window guard (checkOffHours), an orthogonal concern. A user
// who wants to "trade" outside market hours must use Variety="amo".
//
// Fail-open paths:
//   - tzdata missing in container → allow (deployment-config issue, not
//     the user's fault; the static per-order/daily caps still apply).
func (g *Guard) checkMarketHours(req OrderCheckRequest) CheckResult {
	if isAMOVariety(req.Variety) {
		return CheckResult{Allowed: true}
	}
	ist, err := loadMarketHoursIST()
	if err != nil {
		return CheckResult{Allowed: true}
	}
	now := g.clock().In(ist)
	weekday := now.Weekday()
	if weekday == time.Saturday || weekday == time.Sunday {
		return CheckResult{
			Allowed: false, Reason: ReasonMarketClosed,
			Message: fmt.Sprintf(
				"NSE/BSE equity-cash market is closed on %s. Use variety=\"amo\" to queue an After-Market Order for the next session, or wait for Monday open (09:15 IST). Current IST: %s.",
				weekday, now.Format("Mon 15:04 MST")),
		}
	}
	minuteOfDay := now.Hour()*60 + now.Minute()
	if minuteOfDay < marketOpenIST || minuteOfDay >= marketCloseIST {
		return CheckResult{
			Allowed: false, Reason: ReasonMarketClosed,
			Message: fmt.Sprintf(
				"NSE/BSE equity-cash market is closed (hours: 09:15–15:30 IST, Mon–Fri). Use variety=\"amo\" to queue an After-Market Order for the next session. Current IST: %s.",
				now.Format("Mon 15:04 MST")),
		}
	}
	return CheckResult{Allowed: true}
}

// PinClockToMarketHoursForTest is a cross-package test helper that pins
// g.clock() to the most recent weekday at 10:30 IST so the market_hours
// (T1) and off_hours (02:00–06:00 IST) checks pass deterministically on
// weekend or deep-night CI runs. Use from any test package that
// constructs a Guard via NewGuard and exercises the order-checking path.
//
// The pin rolls back to Friday on Sat/Sun so a test that records relative
// timestamps via `time.Now()` (DayResetAt, RecentOrders, etc.) still sees
// the same date the guard sees — preserving relative-time semantics that
// the day-reset boundary tests rely on.
//
// Naming includes "ForTest" so it is unambiguous in IDE/godoc that this
// is a fixture utility, not a production setter. Production code paths
// MUST NOT call this — they should leave g.clock at its time.Now default.
func PinClockToMarketHoursForTest(g *Guard) {
	ist, err := loadMarketHoursIST()
	if err != nil {
		// tzdata missing — let the test author see this as a clearly
		// wrong "clock pinned to UTC zero-value" rather than silently
		// no-op. The market-hours check itself fails open on the same
		// path, but that is for production resilience, not test hygiene.
		ist = time.UTC
	}
	g.SetClock(func() time.Time {
		now := time.Now().In(ist)
		switch now.Weekday() {
		case time.Saturday:
			now = now.AddDate(0, 0, -1)
		case time.Sunday:
			now = now.AddDate(0, 0, -2)
		}
		return time.Date(now.Year(), now.Month(), now.Day(), 10, 30, 0, 0, ist)
	})
}
