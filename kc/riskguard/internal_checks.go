package riskguard

import (
	"fmt"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// internal_checks.go — the 10+ internal check*(...) methods that each
// built-in Check adapter (see check.go for the adapter types and their
// Order() precedence) calls into. Extracted from guard.go in the 2026-04
// cohesion split so the evaluation rules sit in one focused file,
// separate from the Guard struct definition, CheckOrder orchestration,
// and the tracker/limit/freeze bookkeeping.
//
// Each function takes/returns only what it needs — CheckResult is the
// uniform return so the adapters in check.go can treat them
// interchangeably. Pure file move — no behavior change.

// checkKillSwitch rejects when the user's TradingFrozen flag is set —
// the per-user equivalent of the global freeze. Returns Allowed=false
// with the stored FrozenReason so users see why.
func (g *Guard) checkKillSwitch(email string) CheckResult {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if l, ok := g.limits[email]; ok && l.TradingFrozen {
		reason := l.FrozenReason
		if reason == "" {
			reason = "no reason given"
		}
		return CheckResult{
			Allowed: false, Reason: ReasonTradingFrozen,
			Message: fmt.Sprintf("Trading is frozen for your account. Reason: %s. Contact admin.", reason),
		}
	}
	return CheckResult{Allowed: true}
}

// checkConfirmationRequired enforces RequireConfirmAllOrders. When the
// effective user limit has the flag set (default true), any order without
// req.Confirmed=true is rejected. This is the primary defence against silent
// prompt-injection auto-execution: the caller (middleware) must surface a
// user-facing confirmation step and pass the ack through.
func (g *Guard) checkConfirmationRequired(req OrderCheckRequest) CheckResult {
	limits := g.GetEffectiveLimits(req.Email)
	if !limits.RequireConfirmAllOrders {
		return CheckResult{Allowed: true}
	}
	if req.Confirmed {
		return CheckResult{Allowed: true}
	}
	return CheckResult{
		Allowed: false,
		Reason:  ReasonConfirmationRequired,
		Message: "Order confirmation required: every order must be explicitly acknowledged. Pass confirm=true to proceed.",
	}
}

func (g *Guard) checkOrderValue(req OrderCheckRequest) CheckResult {
	// Skip for MARKET orders (price unknown at submission time)
	if !req.Price.IsPositive() {
		return CheckResult{Allowed: true}
	}
	limits := g.GetEffectiveLimits(req.Email)
	// Currency-aware comparison: scale Money by Quantity, then compare to
	// the user's MaxSingleOrderINR cap. Cross-currency would error and we
	// treat that as "unable to verify, allow" — but in this code path both
	// sides are INR-denominated, so the error path is unreachable in practice.
	value := req.Price.Multiply(float64(req.Quantity))
	exceeds, err := value.GreaterThan(limits.MaxSingleOrderINR)
	if err == nil && exceeds {
		return CheckResult{
			Allowed: false, Reason: ReasonOrderValue,
			Message: fmt.Sprintf("Order value Rs %.0f exceeds limit Rs %.0f", value.Float64(), limits.MaxSingleOrderINR.Float64()),
		}
	}
	return CheckResult{Allowed: true}
}

func (g *Guard) checkQuantityLimit(req OrderCheckRequest) CheckResult {
	if g.freezeLookup == nil || req.Exchange == "" || req.Tradingsymbol == "" {
		return CheckResult{Allowed: true} // no instrument data — fail open
	}
	freezeQty, found := g.freezeLookup.GetFreezeQuantity(req.Exchange, req.Tradingsymbol)
	if !found || freezeQty == 0 {
		return CheckResult{Allowed: true}
	}
	if req.Quantity < 0 || req.Quantity > int(freezeQty) {
		return CheckResult{
			Allowed: false, Reason: ReasonQuantityLimit,
			Message: fmt.Sprintf("Quantity %d exceeds freeze limit %d for %s:%s", req.Quantity, freezeQty, req.Exchange, req.Tradingsymbol),
		}
	}
	return CheckResult{Allowed: true}
}

func (g *Guard) checkDailyOrderCount(email string) CheckResult {
	limits := g.GetEffectiveLimits(email)
	g.mu.Lock()
	t := g.getOrCreateTracker(email)
	didReset := g.maybeResetDay(t)
	count := t.DailyOrderCount
	dispatcher := g.events
	g.mu.Unlock()
	g.dispatchDailyResetIfNeeded(email, didReset, dispatcher)
	if count >= limits.MaxOrdersPerDay {
		return CheckResult{
			Allowed: false, Reason: ReasonDailyOrderLimit,
			Message: fmt.Sprintf("You have placed %d orders today (limit: %d). Resets at next market open.", count, limits.MaxOrdersPerDay),
		}
	}
	return CheckResult{Allowed: true}
}

func (g *Guard) checkRateLimit(email string) CheckResult {
	limits := g.GetEffectiveLimits(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)

	// Prune orders older than 60 seconds
	cutoff := time.Now().Add(-60 * time.Second)
	start := 0
	for start < len(t.RecentOrders) && t.RecentOrders[start].Before(cutoff) {
		start++
	}
	t.RecentOrders = t.RecentOrders[start:]

	if len(t.RecentOrders) >= limits.MaxOrdersPerMinute {
		return CheckResult{
			Allowed: false, Reason: ReasonRateLimit,
			Message: fmt.Sprintf("%d orders in last minute (limit: %d)", len(t.RecentOrders), limits.MaxOrdersPerMinute),
		}
	}
	return CheckResult{Allowed: true}
}

// checkClientOrderIDDuplicate enforces user-supplied idempotency keys. When
// ClientOrderID is empty, the check is a no-op (backward-compatible). When
// present, (email, ClientOrderID) is hashed and recorded; a second call with
// the same pair inside DefaultDedupTTL is rejected.
//
// This is the deterministic retry-safety primitive stolen from Alpaca's
// client_order_id: the user says "this is submission X; don't let me
// double-book X" and the server enforces it without needing to guess from
// symbol/qty/price coincidences.
func (g *Guard) checkClientOrderIDDuplicate(req OrderCheckRequest) CheckResult {
	if req.ClientOrderID == "" {
		return CheckResult{Allowed: true} // no idempotency key — allow
	}
	if g.dedup == nil {
		return CheckResult{Allowed: true} // defensive: uninitialized guard
	}
	email := strings.ToLower(req.Email)
	if g.dedup.SeenOrAdd(email, req.ClientOrderID) {
		return CheckResult{
			Allowed: false, Reason: ReasonDuplicateOrder,
			Message: fmt.Sprintf("client_order_id %q already submitted within the last %s — this looks like a retry of a prior order. If this is a new order, use a different client_order_id.",
				req.ClientOrderID, DefaultDedupTTL),
		}
	}
	return CheckResult{Allowed: true}
}

func (g *Guard) checkDuplicateOrder(email string, req OrderCheckRequest) CheckResult {
	limits := g.GetEffectiveLimits(email)
	if limits.DuplicateWindowSecs <= 0 {
		return CheckResult{Allowed: true}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)

	cutoff := time.Now().Add(-time.Duration(limits.DuplicateWindowSecs) * time.Second)
	// Prune old entries
	start := 0
	for start < len(t.RecentParams) && t.RecentParams[start].PlacedAt.Before(cutoff) {
		start++
	}
	t.RecentParams = t.RecentParams[start:]

	for _, prev := range t.RecentParams {
		if prev.Exchange == req.Exchange &&
			prev.Tradingsymbol == req.Tradingsymbol &&
			prev.TransactionType == req.TransactionType &&
			prev.Quantity == req.Quantity {
			ago := int(time.Since(prev.PlacedAt).Seconds())
			return CheckResult{
				Allowed: false, Reason: ReasonDuplicateOrder,
				Message: fmt.Sprintf("Same order (%s %s %s qty %d) placed %d seconds ago",
					req.TransactionType, req.Exchange, req.Tradingsymbol, req.Quantity, ago),
			}
		}
	}
	return CheckResult{Allowed: true}
}

func (g *Guard) checkDailyValue(email string, req OrderCheckRequest) CheckResult {
	if !req.Price.IsPositive() {
		return CheckResult{Allowed: true} // MARKET orders — price unknown
	}
	limits := g.GetEffectiveLimits(email)
	// Scale Money price by qty for the order's notional. DailyPlacedValue
	// is still float (Slice 3 will Money-ify it), so we drop to float
	// only on the cumulative + comparison path.
	orderValue := req.Price.Multiply(float64(req.Quantity)).Float64()

	g.mu.Lock()
	t := g.getOrCreateTracker(email)
	didReset := g.maybeResetDay(t)
	placed := t.DailyPlacedValue
	dispatcher := g.events
	g.mu.Unlock()
	g.dispatchDailyResetIfNeeded(email, didReset, dispatcher)

	cumulative := domain.NewINR(placed + orderValue)
	exceeds, err := cumulative.GreaterThan(limits.MaxDailyValueINR)
	if err == nil && exceeds {
		return CheckResult{
			Allowed: false, Reason: ReasonDailyValueLimit,
			Message: fmt.Sprintf("Cumulative placed value Rs %.0f + this order Rs %.0f exceeds daily limit Rs %.0f",
				placed, orderValue, limits.MaxDailyValueINR.Float64()),
		}
	}
	return CheckResult{Allowed: true}
}

// checkAnomalyMultiplier compares this order's value against the user's
// rolling 30-day baseline. Blocks only when BOTH conditions hold:
//  1. order value > μ + 3σ (statistically improbable given their history)
//  2. order value > 10 × μ (magnitude jump, not just stdev noise)
//
// Fail-open paths:
//   - no BaselineProvider configured → allow (DevMode / tests)
//   - MARKET order (Price == 0) → allow, no known value to compare
//   - insufficient baseline rows → provider returns (0, 0, count) → allow
//
// Rationale for AND-not-OR: a user who only trades exactly Rs 5,000 lots
// has σ = 0, so ANY larger order is "infinitely many σ above the mean".
// Conversely, a user with wild Rs 5k–Rs 5L range already has σ so large
// that 10×mean stays within 3σ. Requiring both conditions gives a cleaner
// signal: "this order is far from center AND much larger in magnitude".
func (g *Guard) checkAnomalyMultiplier(req OrderCheckRequest) CheckResult {
	if g.baseline == nil {
		return CheckResult{Allowed: true} // no provider → silent no-op
	}
	if !req.Price.IsPositive() {
		return CheckResult{Allowed: true} // MARKET — skip
	}
	orderValue := req.Price.Multiply(float64(req.Quantity)).Float64()
	mean, stdev, _ := g.baseline.UserOrderStats(strings.ToLower(req.Email), anomalyBaselineDays)
	if mean <= 0 {
		// Insufficient history (or unknown user). Fail open — the static
		// per-order and daily-value caps still apply.
		return CheckResult{Allowed: true}
	}

	sigmaThreshold := mean + anomalySigmaMultiplier*stdev
	meanThreshold := anomalyMeanMultiplier * mean

	if orderValue > sigmaThreshold && orderValue > meanThreshold {
		return CheckResult{
			Allowed: false, Reason: ReasonAnomalyHigh,
			Message: fmt.Sprintf(
				"Order value Rs %.0f is a statistical anomaly: your 30-day baseline mean is Rs %.0f (σ=Rs %.0f), so this order is both > %.0fx mean and > mean+%.0fσ. If legitimate, place a smaller order to rebuild baseline or contact admin.",
				orderValue, mean, stdev, anomalyMeanMultiplier, anomalySigmaMultiplier),
		}
	}
	return CheckResult{Allowed: true}
}

// checkOffHours hard-blocks any order placed between 02:00 and 06:00 IST,
// unless the user has explicitly opted in via UserLimits.AllowOffHours.
// Uses Asia/Kolkata explicitly so the block works regardless of the host's
// local timezone (Fly.io machines run UTC).
//
// The window intentionally straddles the time band when:
//   - legitimate manual trading has stopped (nobody's awake to approve)
//   - morning-prep automation hasn't started yet (SIPs fire after 09:00)
//   - market orders cannot execute anyway (open is 09:15 IST)
//
// Any activity in this window is therefore either malfunctioning automation
// or an adversary exploiting the owner being asleep. Blocking it costs the
// legitimate user nothing (no market during this window) but deprives an
// attacker of the quietest attack window.
func (g *Guard) checkOffHours(req OrderCheckRequest) CheckResult {
	limits := g.GetEffectiveLimits(req.Email)
	if limits.AllowOffHours {
		return CheckResult{Allowed: true}
	}
	ist, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		// If tzdata is missing in the container, fail open rather than
		// lock everyone out. This is a deployment-level configuration
		// issue, not an attacker's fault.
		return CheckResult{Allowed: true}
	}
	nowIST := g.clock().In(ist)
	hour := nowIST.Hour()
	if hour >= offHoursStartIST && hour < offHoursEndIST {
		return CheckResult{
			Allowed: false, Reason: ReasonOffHoursBlocked,
			Message: fmt.Sprintf(
				"Orders are blocked between %02d:00 and %02d:00 IST. Current IST time: %s. Enable AllowOffHours in risk_limits to opt in to 24/7 trading.",
				offHoursStartIST, offHoursEndIST, nowIST.Format("15:04 MST")),
		}
	}
	return CheckResult{Allowed: true}
}
