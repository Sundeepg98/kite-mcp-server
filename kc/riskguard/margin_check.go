package riskguard

// margin_check.go — optional pre-trade margin rejection (T5).
//
// Background
// ==========
// `mcp/margin_tools.go GetOrderChargesQuery` already exists, but
// place_order doesn't auto-call it. Insufficient-margin errors
// surface only after a Kite round-trip — wasting per-second rate
// headroom and confusing users who see "Order Placed → Order
// Rejected" sequences.
//
// T5 wires an optional pre-trade margin check. Disabled by default
// (the brief: "gate by user opt-in flag in Config or per-tier") so
// that DevMode and tests don't trip on it. When enabled, the check
// computes order notional (Quantity * Price) and rejects if it
// exceeds the user's available margin.
//
// MARKET orders skip the check — Price=0 means notional can't be
// computed cheaply; broker-side margin enforcement still applies.
//
// Slot 325 — between order_value (300) and circuit_limit (350).
// Cheap reject-paths short-circuit ahead.

import "fmt"

// OrderMarginCheck is the Check.Order slot.
const OrderMarginCheck = 325

// MarginLookup is the narrow port the margin check needs. Production
// binds this to a periodically-refreshed GetMargins cache; tests stub.
//
// found=false → "no margin data" → check falls open.
type MarginLookup interface {
	// GetAvailableMargin returns the user's available margin (across
	// equity + commodity, summed). Single value rather than per-segment
	// keeps the interface minimal — the check's notional comparison
	// doesn't need per-segment routing yet.
	GetAvailableMargin(email string) (float64, bool)
}

// marginCheck implements the optional pre-trade margin rule.
//
// RecordOnRejection is FALSE. Insufficient margin is a user-state
// signal (legitimate margin exhaustion from prior fills), not a fat-
// finger or hostile-script pattern. Counting toward auto-freeze
// would punish a user for normal trading; same posture as
// confirmation_required (policy gate, not limit violation).
//
// Holds *Guard pointer so SetMarginLookup / SetMarginCheckEnabled
// can wire the dependencies AFTER NewGuard.
type marginCheck struct {
	g *Guard
}

func (c *marginCheck) Name() string             { return "margin_check" }
func (c *marginCheck) Order() int               { return OrderMarginCheck }
func (c *marginCheck) RecordOnRejection() bool  { return false }

// Evaluate enforces the margin gate. Skips when:
//   - Check is disabled (default).
//   - No lookup is wired (DevMode).
//   - Order is MARKET (Price=0; notional incomputable cheaply).
//   - Lookup misses for the user (fail open).
func (c *marginCheck) Evaluate(req OrderCheckRequest) CheckResult {
	c.g.mu.RLock()
	enabled := c.g.marginCheckEnabled
	lookup := c.g.marginLookup
	c.g.mu.RUnlock()
	if !enabled || lookup == nil || !req.Price.IsPositive() || req.Quantity <= 0 {
		return CheckResult{Allowed: true}
	}
	available, found := lookup.GetAvailableMargin(req.Email)
	if !found {
		return CheckResult{Allowed: true}
	}
	// Drop Money to float at this boundary — margin lookup returns float64.
	required := req.Price.Multiply(float64(req.Quantity)).Float64()
	if required > available {
		return CheckResult{
			Allowed: false,
			Reason:  ReasonInsufficientMargin,
			Message: fmt.Sprintf(
				"Insufficient margin: order requires Rs %.0f but only Rs %.0f is available. "+
					"Reduce quantity or fund the account before retrying.",
				required, available,
			),
		}
	}
	return CheckResult{Allowed: true}
}
