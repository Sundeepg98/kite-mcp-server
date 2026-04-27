package riskguard

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// trackers.go — per-user in-memory bookkeeping: the UserTracker sliding
// windows (recent orders, rejections, duplicate signatures) and the
// UserStatus read-side snapshot. Extracted from guard.go in the 2026-04
// cohesion split so the mutable per-user state lives in one focused
// file, separate from check-pipeline orchestration (guard.go), limits
// persistence (limits.go), and freeze lifecycle (lifecycle.go).
//
// Pure file move — no behavior change.

// recentOrder captures the signature of a placed order for duplicate detection.
type recentOrder struct {
	Exchange        string
	Tradingsymbol   string
	TransactionType string
	Quantity        int
	PlacedAt        time.Time
}

// UserTracker holds in-memory per-user trading state.
//
// DailyPlacedValue is typed domain.Money (Slice 3 of the Money sweep).
// Cumulative cap-checking happens via Money.Add / Money.GreaterThan; the
// JSON boundary (UserStatus, see below) drops to float64 via .Float64().
type UserTracker struct {
	DailyOrderCount  int
	DayResetAt       time.Time
	RecentOrders     []time.Time   // sliding window for rate limiting
	RecentParams     []recentOrder // sliding window for duplicate detection
	DailyPlacedValue domain.Money  // cumulative order value placed today
	RecentRejections []time.Time   // sliding window for circuit breaker auto-freeze
}

// UserStatus holds a snapshot of a user's current risk state for read-only reporting.
//
// DailyPlacedValue is typed domain.Money internally but serialised as
// float64 via the custom MarshalJSON below so the dashboard SSE feed and
// admin tools see no behavioural change.
type UserStatus struct {
	DailyOrderCount  int          `json:"daily_order_count"`
	DailyPlacedValue domain.Money `json:"-"`
	IsFrozen         bool         `json:"is_frozen"`
	FrozenBy         string       `json:"frozen_by"`
	FrozenReason     string       `json:"frozen_reason"`
	FrozenAt         time.Time    `json:"frozen_at,omitempty"`
}

// MarshalJSON emits DailyPlacedValue as a raw float64 to preserve the
// existing JSON wire contract (`{"daily_placed_value": 12345.67, ...}`).
// Internal callers should keep working with the Money value directly via
// the struct field; only JSON consumers see the primitive.
func (s UserStatus) MarshalJSON() ([]byte, error) {
	type alias UserStatus
	return json.Marshal(struct {
		alias
		DailyPlacedValue float64 `json:"daily_placed_value"`
	}{
		alias:            alias(s),
		DailyPlacedValue: s.DailyPlacedValue.Float64(),
	})
}

// UnmarshalJSON reconstructs DailyPlacedValue as an INR Money from the
// wire-format float64. Used by tests and any admin tool that round-trips
// a UserStatus payload (e.g. fixtures captured from a running server).
func (s *UserStatus) UnmarshalJSON(data []byte) error {
	type alias UserStatus
	aux := struct {
		*alias
		DailyPlacedValue float64 `json:"daily_placed_value"`
	}{
		alias: (*alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	s.DailyPlacedValue = domain.NewINR(aux.DailyPlacedValue)
	return nil
}

// GetUserStatus returns a snapshot of the user's current daily order count,
// placed value, and freeze state.
func (g *Guard) GetUserStatus(email string) UserStatus {
	email = strings.ToLower(email)
	g.mu.Lock()
	t := g.getOrCreateTracker(email)
	didReset := g.maybeResetDay(t)
	dispatcher := g.events

	status := UserStatus{
		DailyOrderCount:  t.DailyOrderCount,
		DailyPlacedValue: t.DailyPlacedValue,
	}
	if l, ok := g.limits[email]; ok {
		status.IsFrozen = l.TradingFrozen
		status.FrozenBy = l.FrozenBy
		status.FrozenReason = l.FrozenReason
		status.FrozenAt = l.FrozenAt
	}
	g.mu.Unlock()
	g.dispatchDailyResetIfNeeded(email, didReset, dispatcher)
	return status
}

// getOrCreateTracker returns the per-email tracker, creating it on demand.
// Caller must hold g.mu (writer) — the tracker map itself is guarded by mu.
func (g *Guard) getOrCreateTracker(email string) *UserTracker {
	t, ok := g.trackers[email]
	if !ok {
		t = &UserTracker{DayResetAt: time.Now()}
		g.trackers[email] = t
	}
	return t
}

// maybeResetDay resets the daily counter if we've crossed 9:15 AM IST since
// last reset. Uses g.clock so tests can drive the reset deterministically.
//
// Returns true when an actual reset occurred (DayResetAt was before the
// trading-day boundary, counters were rolled to zero). Callers that hold
// g.mu can pass this signal up to dispatch RiskguardDailyCounterResetEvent
// AFTER releasing the lock — handlers must never run under the riskguard
// mutex. False return ⇒ no reset, no event.
func (g *Guard) maybeResetDay(t *UserTracker) bool {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	now := g.clock().In(ist)
	resetTime := time.Date(now.Year(), now.Month(), now.Day(), 9, 15, 0, 0, ist)
	// If before 9:15 today, use yesterday's 9:15
	if now.Before(resetTime) {
		resetTime = resetTime.AddDate(0, 0, -1)
	}
	if t.DayResetAt.Before(resetTime) {
		t.DailyOrderCount = 0
		t.DailyPlacedValue = domain.Money{} // zero-Money sentinel on reset
		t.DayResetAt = now
		return true
	}
	return false
}
