package riskguard

// circuit_limit.go — pre-trade exchange-circuit rejection (T2).
//
// Background
// ==========
// Every NSE/BSE-traded instrument has a daily price band ("circuit
// limit") — usually ±5%, ±10%, or ±20% of the previous-day close. The
// exchange refuses any order priced outside the band (ELM ratio
// surveillance + circuit-breaker rule). Pre-T2 we relied on Kite to
// surface the rejection — every breach cost a round trip and counted
// against per-second rate caps. T2 catches the breach at riskguard.
//
// The circuit data IS already returned by Kite's `quote` endpoint
// (broker.Quote.LowerCircuitLimit / UpperCircuitLimit) — it just
// wasn't being consulted. T2 wires it via a new CircuitLookup port
// that the broker-quote-cache adapter implements; nil-safe.
//
// Slot
// ====
// OrderCircuitLimit = 350 — between order_value (300) and
// quantity_limit (400). Cheap reject-paths short-circuit ahead of the
// circuit lookup; the circuit consultation itself is ~free (in-memory
// map lookup) but order_value rejection is a single cmp.

import "fmt"

// OrderCircuitLimit is the Check.Order slot for the circuit rule.
const OrderCircuitLimit = 350

// CircuitLookup is the narrow port the circuit check needs. Production
// binds this to a thin wrapper over broker.Quote responses cached in
// the LTP cache; tests pass a stub map. Returns (lower, upper, found).
//
// found=false signals "no data" — the check falls open. Better to pass
// a real order than reject one because the cache hasn't warmed.
type CircuitLookup interface {
	GetCircuitLimits(exchange, tradingsymbol string) (lower, upper float64, found bool)
}

// circuitLimitCheck implements the exchange-circuit rule as a Check.
//
// RecordOnRejection is true: a user repeatedly trying to slam through
// the circuit is either fat-fingered or hostile; either way deserves
// rate-limit pressure (auto-freeze on 3 limit rejections in 5 min).
//
// Holds *Guard pointer so SetCircuitLookup can wire the lookup AFTER
// NewGuard — same pattern as otrBandCheck.
type circuitLimitCheck struct {
	g *Guard
}

func (c *circuitLimitCheck) Name() string             { return "circuit_limit" }
func (c *circuitLimitCheck) Order() int               { return OrderCircuitLimit }
func (c *circuitLimitCheck) RecordOnRejection() bool  { return true }

// Evaluate enforces the circuit. Skips MARKET orders (Price=0; the
// match engine fills at prevailing price which is by definition inside
// the band). Skips when no lookup is wired or the instrument has no
// circuit data (fail open).
//
// Boundary semantics: a price exactly equal to lower or upper passes.
// Kite's match engine accepts orders AT the band; rejection only
// applies strictly outside.
func (c *circuitLimitCheck) Evaluate(req OrderCheckRequest) CheckResult {
	c.g.mu.RLock()
	lookup := c.g.circuitLookup
	c.g.mu.RUnlock()
	if lookup == nil || req.Price <= 0 {
		return CheckResult{Allowed: true}
	}
	lower, upper, found := lookup.GetCircuitLimits(req.Exchange, req.Tradingsymbol)
	if !found || upper <= 0 {
		return CheckResult{Allowed: true}
	}
	if req.Price < lower || req.Price > upper {
		return CheckResult{
			Allowed: false,
			Reason:  ReasonCircuitBreached,
			Message: fmt.Sprintf(
				"Order price Rs %.2f is outside the exchange circuit band [Rs %.2f, Rs %.2f]. "+
					"Kite would reject this order at the gateway.",
				req.Price, lower, upper,
			),
		}
	}
	return CheckResult{Allowed: true}
}
