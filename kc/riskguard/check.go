package riskguard

// Check is the interface for a single pre-trade risk rule.
//
// Checks are evaluated in Order() ascending; the first check to return a
// CheckResult with Allowed=false wins and short-circuits the chain. This
// matches the historical sequential if-chain behaviour in CheckOrder, so
// converting a hard-coded check to a Check-interface type is purely a
// structural refactor — no semantic change.
//
// The interface is intentionally narrow so third-party plugins (e.g. a
// premium-tier "no-options-near-expiry" check, a custom options-strike
// block, a compliance-team approval gate) can register new checks via
// Guard.RegisterCheck without touching the riskguard package.
//
// RecordOnRejection distinguishes "policy rejections" (kill-switch,
// confirmation-required) that must NOT count toward the auto-freeze
// circuit breaker from "limit violations" (order-value, quantity, rate,
// daily-value, anomaly, off-hours) that DO count. Preserving this
// distinction keeps the existing auto-freeze semantics exact: a user
// whose trading is already frozen does not get "auto-frozen again" and
// a user who simply forgot to confirm isn't penalised toward an eventual
// lockout.
type Check interface {
	// Name is a stable identifier for logs, metrics, and admin listings.
	// Use snake_case; must be unique within a Guard's registered set.
	Name() string

	// Order determines evaluation position (ascending). Built-in checks
	// occupy 100..1200 in steps of 100, so plugins can interleave at
	// 150, 250, ... without displacing built-ins. Use values <0 to run
	// before every built-in, or >1200 to run after all built-ins.
	Order() int

	// RecordOnRejection reports whether a not-allowed result should be
	// counted toward the auto-freeze circuit-breaker (3 rejections in
	// 5 min → freeze). Policy checks (kill-switch, confirmation gate)
	// return false; limit checks return true. Custom checks typically
	// return true.
	RecordOnRejection() bool

	// Evaluate runs the rule against req. A result with Allowed=true
	// passes the rule; Allowed=false short-circuits the chain and is
	// surfaced to the caller.
	Evaluate(req OrderCheckRequest) CheckResult
}

// Built-in check order constants. Spaced in increments of 100 so
// plugins can interleave at intermediate positions without having to
// renumber built-ins. Values are stable public API — changing one is a
// semver-relevant behaviour shift because it re-orders rejection
// precedence for callers relying on which reason surfaces first when
// multiple rules would reject.
const (
	OrderKillSwitch            = 100  // user trading frozen
	OrderConfirmationRequired  = 200  // explicit confirm=true required
	OrderOrderValue            = 300  // per-order notional cap
	OrderQuantityLimit         = 400  // exchange freeze-quantity cap
	OrderDailyOrderCount       = 500  // per-day order-count cap
	OrderPerSecondRate         = 600  // 9-orders-per-calendar-second (SEBI)
	OrderRateLimit             = 700  // per-minute order rate
	OrderClientOrderIDDup      = 800  // user-supplied idempotency key
	OrderDuplicateOrder        = 900  // time-based params-hash duplicate
	OrderDailyValue            = 1000 // per-day cumulative notional
	OrderAnomalyMultiplier     = 1100 // rolling baseline statistical anomaly
	OrderOffHours              = 1200 // 02:00–06:00 IST hard-block
	OrderMarketHours           = 1300 // T1: NSE/BSE market-hours rejection (AMO bypasses)
)

// --- Built-in Check adapters ---
//
// Each adapter is a thin pointer-to-Guard wrapper that delegates to the
// pre-existing checkXxx method. Keeping the underlying methods intact
// preserves the existing test surface (per_second_test.go directly calls
// g.checkPerSecondRate) and means the refactor is genuinely mechanical:
// the CheckOrder loop replaces a sequence of inlined method calls with
// an iterator over the same methods, wrapped in a uniform interface.

// killSwitchCheck wraps g.checkKillSwitch.
// Policy check: rejection does not count toward auto-freeze.
type killSwitchCheck struct{ g *Guard }

func (c *killSwitchCheck) Name() string              { return "kill_switch" }
func (c *killSwitchCheck) Order() int                { return OrderKillSwitch }
func (c *killSwitchCheck) RecordOnRejection() bool   { return false }
func (c *killSwitchCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkKillSwitch(lowerEmail(req.Email))
}

// confirmationRequiredCheck wraps g.checkConfirmationRequired.
// Policy check: rejection does not count toward auto-freeze.
type confirmationRequiredCheck struct{ g *Guard }

func (c *confirmationRequiredCheck) Name() string            { return "confirmation_required" }
func (c *confirmationRequiredCheck) Order() int              { return OrderConfirmationRequired }
func (c *confirmationRequiredCheck) RecordOnRejection() bool { return false }
func (c *confirmationRequiredCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkConfirmationRequired(req)
}

// orderValueCheck wraps g.checkOrderValue.
type orderValueCheck struct{ g *Guard }

func (c *orderValueCheck) Name() string            { return "order_value" }
func (c *orderValueCheck) Order() int              { return OrderOrderValue }
func (c *orderValueCheck) RecordOnRejection() bool { return true }
func (c *orderValueCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkOrderValue(req)
}

// quantityLimitCheck wraps g.checkQuantityLimit.
type quantityLimitCheck struct{ g *Guard }

func (c *quantityLimitCheck) Name() string            { return "quantity_limit" }
func (c *quantityLimitCheck) Order() int              { return OrderQuantityLimit }
func (c *quantityLimitCheck) RecordOnRejection() bool { return true }
func (c *quantityLimitCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkQuantityLimit(req)
}

// dailyOrderCountCheck wraps g.checkDailyOrderCount.
type dailyOrderCountCheck struct{ g *Guard }

func (c *dailyOrderCountCheck) Name() string            { return "daily_order_count" }
func (c *dailyOrderCountCheck) Order() int              { return OrderDailyOrderCount }
func (c *dailyOrderCountCheck) RecordOnRejection() bool { return true }
func (c *dailyOrderCountCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkDailyOrderCount(lowerEmail(req.Email))
}

// perSecondRateCheck wraps g.checkPerSecondRate.
type perSecondRateCheck struct{ g *Guard }

func (c *perSecondRateCheck) Name() string            { return "per_second_rate" }
func (c *perSecondRateCheck) Order() int              { return OrderPerSecondRate }
func (c *perSecondRateCheck) RecordOnRejection() bool { return true }
func (c *perSecondRateCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkPerSecondRate(lowerEmail(req.Email))
}

// rateLimitCheck wraps g.checkRateLimit.
type rateLimitCheck struct{ g *Guard }

func (c *rateLimitCheck) Name() string            { return "rate_limit" }
func (c *rateLimitCheck) Order() int              { return OrderRateLimit }
func (c *rateLimitCheck) RecordOnRejection() bool { return true }
func (c *rateLimitCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkRateLimit(lowerEmail(req.Email))
}

// clientOrderIDDupCheck wraps g.checkClientOrderIDDuplicate.
type clientOrderIDDupCheck struct{ g *Guard }

func (c *clientOrderIDDupCheck) Name() string            { return "client_order_id_duplicate" }
func (c *clientOrderIDDupCheck) Order() int              { return OrderClientOrderIDDup }
func (c *clientOrderIDDupCheck) RecordOnRejection() bool { return true }
func (c *clientOrderIDDupCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkClientOrderIDDuplicate(req)
}

// duplicateOrderCheck wraps g.checkDuplicateOrder.
type duplicateOrderCheck struct{ g *Guard }

func (c *duplicateOrderCheck) Name() string            { return "duplicate_order" }
func (c *duplicateOrderCheck) Order() int              { return OrderDuplicateOrder }
func (c *duplicateOrderCheck) RecordOnRejection() bool { return true }
func (c *duplicateOrderCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkDuplicateOrder(lowerEmail(req.Email), req)
}

// dailyValueCheck wraps g.checkDailyValue.
type dailyValueCheck struct{ g *Guard }

func (c *dailyValueCheck) Name() string            { return "daily_value" }
func (c *dailyValueCheck) Order() int              { return OrderDailyValue }
func (c *dailyValueCheck) RecordOnRejection() bool { return true }
func (c *dailyValueCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkDailyValue(lowerEmail(req.Email), req)
}

// anomalyMultiplierCheck wraps g.checkAnomalyMultiplier.
type anomalyMultiplierCheck struct{ g *Guard }

func (c *anomalyMultiplierCheck) Name() string            { return "anomaly_multiplier" }
func (c *anomalyMultiplierCheck) Order() int              { return OrderAnomalyMultiplier }
func (c *anomalyMultiplierCheck) RecordOnRejection() bool { return true }
func (c *anomalyMultiplierCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkAnomalyMultiplier(req)
}

// offHoursCheck wraps g.checkOffHours.
type offHoursCheck struct{ g *Guard }

func (c *offHoursCheck) Name() string            { return "off_hours" }
func (c *offHoursCheck) Order() int              { return OrderOffHours }
func (c *offHoursCheck) RecordOnRejection() bool { return true }
func (c *offHoursCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkOffHours(req)
}

// marketHoursCheck wraps g.checkMarketHours (T1 in the gap catalogue).
// Rejects any non-AMO order placed outside [09:15, 15:30) IST on a
// weekday. Variety="amo" bypasses; weekends always reject. Holidays are
// NOT enforced — Kite's OMS handles those (avoid stale-calendar
// false-rejects on SEBI-announced special sessions).
type marketHoursCheck struct{ g *Guard }

func (c *marketHoursCheck) Name() string            { return "market_hours" }
func (c *marketHoursCheck) Order() int              { return OrderMarketHours }
func (c *marketHoursCheck) RecordOnRejection() bool { return true }
func (c *marketHoursCheck) Evaluate(req OrderCheckRequest) CheckResult {
	return c.g.checkMarketHours(req)
}

// builtinChecks returns the default Check set pre-registered by NewGuard.
// Listed here (rather than assembled inline in NewGuard) so the list is
// visible in one place for auditors and reviewers. Order of the slice is
// insignificant at registration time because insertCheck sorts by Order();
// the list is simply the canonical set of built-ins.
func builtinChecks(g *Guard) []Check {
	return []Check{
		&killSwitchCheck{g: g},
		&confirmationRequiredCheck{g: g},
		&orderValueCheck{g: g},
		&marginCheck{g: g},       // T5: 325, optional (off by default)
		&circuitLimitCheck{g: g}, // T2: 350, between order_value (300) and quantity_limit (400)
		&quantityLimitCheck{g: g},
		&dailyOrderCountCheck{g: g},
		&perSecondRateCheck{g: g},
		&rateLimitCheck{g: g},
		&clientOrderIDDupCheck{g: g},
		&duplicateOrderCheck{g: g},
		&dailyValueCheck{g: g},
		&otrBandCheck{g: g},  // SEBI OTR Apr 2026 — reads g.ltpLookup at eval time
		&anomalyMultiplierCheck{g: g},
		&offHoursCheck{g: g},
		&marketHoursCheck{g: g}, // T1: NSE/BSE market-hours rejection (AMO bypasses)
	}
}

// Compile-time assertions that every built-in type satisfies Check. If
// the Check interface ever gains a new method, these will flag every
// adapter that has not been updated.
var (
	_ Check = (*killSwitchCheck)(nil)
	_ Check = (*confirmationRequiredCheck)(nil)
	_ Check = (*orderValueCheck)(nil)
	_ Check = (*marginCheck)(nil)
	_ Check = (*circuitLimitCheck)(nil)
	_ Check = (*quantityLimitCheck)(nil)
	_ Check = (*dailyOrderCountCheck)(nil)
	_ Check = (*perSecondRateCheck)(nil)
	_ Check = (*rateLimitCheck)(nil)
	_ Check = (*clientOrderIDDupCheck)(nil)
	_ Check = (*duplicateOrderCheck)(nil)
	_ Check = (*dailyValueCheck)(nil)
	_ Check = (*otrBandCheck)(nil)
	_ Check = (*anomalyMultiplierCheck)(nil)
	_ Check = (*offHoursCheck)(nil)
	_ Check = (*marketHoursCheck)(nil)
)
