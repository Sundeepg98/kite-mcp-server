package riskguard

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// System defaults — overridable via env vars or per-user DB config.
//
// SECURITY NOTE (Free-tier mitigation for prompt-injection / market-manipulation):
// These values were tightened to address the "sub-cap layering" landmine — an
// adversarial prompt that places many small orders under the per-order cap but
// whose cumulative notional still looks like manipulative layering to SEBI
// surveillance. The previous defaults (Rs 5L cap, 200/day, Rs 10L notional) were
// too permissive for an autonomous agent execution path. Power users can still
// raise their limits per-account via risk_limits overrides.
var SystemDefaults = UserLimits{
	MaxSingleOrderINR:       50000,  // Rs 50,000 (Free tier — was Rs 5,00,000)
	MaxOrdersPerDay:         20,     // Free tier — was 200
	MaxOrdersPerMinute:      10,
	DuplicateWindowSecs:     30,
	MaxDailyValueINR:        200000, // Rs 2,00,000 (Free tier — was Rs 10,00,000)
	AutoFreezeOnLimitHit:    true,
	RequireConfirmAllOrders: true, // Default ON: every order needs an explicit ACK
}

// orderTools lists tools that go through risk checks (same as elicitation).
var orderTools = map[string]bool{
	"place_order": true, "modify_order": true,
	"close_position": true, "close_all_positions": true,
	"place_gtt_order": true, "modify_gtt_order": true,
	"place_mf_order": true, "place_mf_sip": true,
}

// IsOrderTool returns true if the tool should be risk-checked.
func IsOrderTool(name string) bool { return orderTools[name] }

// RejectionReason categorizes why an order was blocked.
type RejectionReason string

const (
	ReasonGlobalFreeze         RejectionReason = "global_freeze"
	ReasonTradingFrozen        RejectionReason = "trading_frozen"
	ReasonOrderValue           RejectionReason = "order_value_limit"
	ReasonQuantityLimit        RejectionReason = "quantity_limit"
	ReasonDailyOrderLimit      RejectionReason = "daily_order_limit"
	ReasonRateLimit            RejectionReason = "rate_limit"
	ReasonDuplicateOrder       RejectionReason = "duplicate_order"
	ReasonDailyValueLimit      RejectionReason = "daily_value_limit"
	ReasonAutoFreeze           RejectionReason = "auto_freeze"
	// ReasonConfirmationRequired blocks silent auto-execution by an agent — the
	// caller must explicitly set Confirmed=true on the OrderCheckRequest (which
	// the middleware populates from a `confirm: true` tool argument the user
	// acknowledged via elicitation).
	ReasonConfirmationRequired RejectionReason = "confirmation_required"
)

const (
	// autoFreezeThreshold is the number of rejections within the window that triggers an auto-freeze.
	autoFreezeThreshold = 3
	// autoFreezeWindow is the time window for counting recent rejections.
	autoFreezeWindow = 5 * time.Minute
)

// CheckResult is returned by the guard for every order attempt.
type CheckResult struct {
	Allowed bool
	Reason  RejectionReason
	Message string
}

// UserLimits holds configurable limits for a user.
type UserLimits struct {
	MaxSingleOrderINR    float64
	MaxOrdersPerDay      int
	MaxOrdersPerMinute   int
	DuplicateWindowSecs  int
	MaxDailyValueINR     float64
	AutoFreezeOnLimitHit bool // when true, auto-freeze after repeated rejections
	// RequireConfirmAllOrders, when true, blocks any order that does not
	// carry an explicit Confirmed=true flag on the OrderCheckRequest. This
	// is the primary defence against silent prompt-injection auto-execution:
	// an agent cannot place an order on behalf of a user without that user
	// explicitly confirming (typically via MCP elicitation). A power user may
	// set this to false per-account to restore "no-ack" behaviour.
	RequireConfirmAllOrders bool
	TradingFrozen           bool
	FrozenBy                string
	FrozenReason            string
	FrozenAt                time.Time
}

// recentOrder captures the signature of a placed order for duplicate detection.
type recentOrder struct {
	Exchange        string
	Tradingsymbol   string
	TransactionType string
	Quantity        int
	PlacedAt        time.Time
}

// UserTracker holds in-memory per-user trading state.
type UserTracker struct {
	DailyOrderCount  int
	DayResetAt       time.Time
	RecentOrders     []time.Time   // sliding window for rate limiting
	RecentParams     []recentOrder // sliding window for duplicate detection
	DailyPlacedValue float64       // cumulative order value placed today
	RecentRejections []time.Time   // sliding window for circuit breaker auto-freeze
}

// FreezeQuantityLookup is an interface for looking up instrument freeze quantities.
// Implemented by instruments.Manager wrapper to avoid direct dependency.
type FreezeQuantityLookup interface {
	GetFreezeQuantity(exchange, tradingsymbol string) (uint32, bool)
}

// AutoFreezeNotifier is called when the circuit breaker auto-freezes a user.
// Implementations should be non-blocking (e.g. send async Telegram message).
type AutoFreezeNotifier func(email, reason string)

// Guard is the central risk management engine.
type Guard struct {
	mu                  sync.RWMutex
	trackers            map[string]*UserTracker
	limits              map[string]*UserLimits // per-user overrides
	freezeLookup        FreezeQuantityLookup
	db                  *alerts.DB
	logger              *slog.Logger
	autoFreezeNotifier  AutoFreezeNotifier
	clock               func() time.Time // defaults to time.Now
	// dedup tracks user-supplied client_order_id idempotency keys. Complements
	// the time-based duplicate detection in checkDuplicateOrder — this one
	// triggers on an explicit user-supplied key, so mcp-remote retries after
	// 504 reuse the same key and are rejected deterministically.
	dedup *Dedup
	// Global trading freeze — blocks ALL users from placing orders.
	globalFrozen   bool
	globalFrozenBy string
	globalFrozenAt     time.Time
	globalFrozenReason string
}

// NewGuard creates a new Guard with system defaults.
func NewGuard(logger *slog.Logger) *Guard {
	return &Guard{
		trackers: make(map[string]*UserTracker),
		limits:   make(map[string]*UserLimits),
		logger:   logger,
		clock:    time.Now,
		dedup:    NewDedup(DefaultDedupTTL),
	}
}

// SetClock overrides the time source (for testing).
func (g *Guard) SetClock(c func() time.Time) { g.clock = c }

// SetDB sets the SQLite database for persisting risk limits.
func (g *Guard) SetDB(db *alerts.DB) { g.db = db }

// SetFreezeQuantityLookup sets the instrument lookup for quantity checks.
func (g *Guard) SetFreezeQuantityLookup(lookup FreezeQuantityLookup) { g.freezeLookup = lookup }

// SetAutoFreezeNotifier registers a callback invoked when the circuit breaker
// auto-freezes a user. The callback receives the user email and the freeze reason.
func (g *Guard) SetAutoFreezeNotifier(fn AutoFreezeNotifier) { g.autoFreezeNotifier = fn }

// FreezeGlobal activates a server-wide trading freeze that blocks ALL users.
func (g *Guard) FreezeGlobal(frozenBy, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.globalFrozen = true
	g.globalFrozenBy = frozenBy
	g.globalFrozenReason = reason
	g.globalFrozenAt = time.Now()
	if g.logger != nil {
		g.logger.Warn("GLOBAL TRADING FREEZE ACTIVATED", "by", frozenBy, "reason", reason)
	}
}

// UnfreezeGlobal lifts the server-wide trading freeze.
func (g *Guard) UnfreezeGlobal() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.globalFrozen = false
	g.globalFrozenBy = ""
	g.globalFrozenReason = ""
	g.globalFrozenAt = time.Time{}
	if g.logger != nil {
		g.logger.Info("Global trading freeze lifted")
	}
}

// IsGloballyFrozen returns true if the server-wide trading freeze is active.
func (g *Guard) IsGloballyFrozen() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.globalFrozen
}

// GlobalFreezeStatus holds the current global freeze state with metadata.
type GlobalFreezeStatus struct {
	IsFrozen bool      `json:"is_frozen"`
	FrozenBy string    `json:"frozen_by,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	FrozenAt time.Time `json:"frozen_at,omitempty"`
}

// GetGlobalFreezeStatus returns the current global freeze status.
func (g *Guard) GetGlobalFreezeStatus() GlobalFreezeStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return GlobalFreezeStatus{
		IsFrozen: g.globalFrozen,
		FrozenBy: g.globalFrozenBy,
		Reason:   g.globalFrozenReason,
		FrozenAt: g.globalFrozenAt,
	}
}

// OrderCheckRequest contains the data needed to evaluate an order.
type OrderCheckRequest struct {
	Email           string
	ToolName        string
	Exchange        string
	Tradingsymbol   string
	TransactionType string // BUY or SELL
	Quantity        int
	Price           float64 // 0 for MARKET orders
	OrderType       string  // MARKET, LIMIT, SL, SL-M
	// Confirmed indicates the user explicitly acknowledged this order (e.g.
	// replied `confirm: true` to an elicitation). When
	// UserLimits.RequireConfirmAllOrders is true, orders without Confirmed=true
	// are rejected with ReasonConfirmationRequired. Wire-set by the middleware
	// from request arguments; direct callers of CheckOrder must set this
	// themselves.
	Confirmed bool
	// ClientOrderID is an optional user-supplied idempotency key (Alpaca-style
	// client_order_id). When present, the guard hashes (email || key) and
	// rejects any duplicate submission within DefaultDedupTTL (15 min) with
	// ReasonDuplicateOrder. Empty means "no idempotency semantics" —
	// backward-compatible with the existing time-based duplicate check.
	ClientOrderID string
}

// CheckOrder runs all safety checks in sequence. Returns on first failure.
// If a limit check fails and the circuit breaker is enabled, the rejection is recorded
// and the user may be auto-frozen after repeated violations.
func (g *Guard) CheckOrder(req OrderCheckRequest) CheckResult {
	// 0. Global freeze — blocks ALL users before any per-user checks.
	if g.IsGloballyFrozen() {
		return CheckResult{
			Allowed: false,
			Reason:  ReasonGlobalFreeze,
			Message: "Trading is globally suspended. Contact the server administrator.",
		}
	}

	email := strings.ToLower(req.Email)

	// 1. Kill switch — not a limit violation, so no auto-freeze logic here
	if r := g.checkKillSwitch(email); !r.Allowed {
		return r
	}
	// 1b. Confirmation gate — blocks silent prompt-injection auto-execution.
	//     Runs AFTER kill-switch so a frozen user still gets "frozen" (do not
	//     leak freeze state via differentiated error codes).
	if r := g.checkConfirmationRequired(req); !r.Allowed {
		return r
	}
	// 2. Order value
	if r := g.checkOrderValue(req); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 3. Quantity limit
	if r := g.checkQuantityLimit(req); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 4. Daily order count
	if r := g.checkDailyOrderCount(email); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 5. Order rate limit (per minute)
	if r := g.checkRateLimit(email); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 6a. Idempotency-key duplicate (client_order_id). Runs before the
	//     time-based duplicate check because it is the most definitive
	//     signal: a user-supplied key reused within TTL is unambiguously a
	//     retry. This is the primary defence against mcp-remote retries
	//     after a 504 gateway timeout re-submitting the same intent.
	if r := g.checkClientOrderIDDuplicate(req); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 6b. Duplicate order detection (time-based, params-hash)
	if r := g.checkDuplicateOrder(email, req); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}
	// 7. Daily cumulative placed value
	if r := g.checkDailyValue(email, req); !r.Allowed {
		g.recordRejection(email)
		if frozen := g.checkAutoFreeze(email); frozen {
			r.Message += " [Account auto-frozen due to repeated violations]"
		}
		return r
	}

	return CheckResult{Allowed: true}
}

// RecordOrder records a successful order for all tracking: daily count, rate window, duplicate detection, and daily value.
func (g *Guard) RecordOrder(email string, req ...OrderCheckRequest) {
	email = strings.ToLower(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	g.maybeResetDay(t)
	t.DailyOrderCount++

	now := time.Now()
	t.RecentOrders = append(t.RecentOrders, now)

	if len(req) > 0 {
		r := req[0]
		t.RecentParams = append(t.RecentParams, recentOrder{
			Exchange:        r.Exchange,
			Tradingsymbol:   r.Tradingsymbol,
			TransactionType: r.TransactionType,
			Quantity:        r.Quantity,
			PlacedAt:        now,
		})
		if r.Price > 0 {
			t.DailyPlacedValue += float64(r.Quantity) * r.Price
		}
	}
}

// Freeze freezes trading for a user.
func (g *Guard) Freeze(email, by, reason string) {
	email = strings.ToLower(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	limits := g.getOrCreateLimits(email)
	limits.TradingFrozen = true
	limits.FrozenBy = by
	limits.FrozenReason = reason
	limits.FrozenAt = time.Now()
	g.persistLimits(email, limits)
}

// Unfreeze unfreezes trading for a user.
func (g *Guard) Unfreeze(email string) {
	email = strings.ToLower(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	limits := g.getOrCreateLimits(email)
	limits.TradingFrozen = false
	limits.FrozenBy = ""
	limits.FrozenReason = ""
	limits.FrozenAt = time.Time{}
	g.persistLimits(email, limits)
}

// IsFrozen returns true if the user's trading is frozen.
func (g *Guard) IsFrozen(email string) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if l, ok := g.limits[strings.ToLower(email)]; ok {
		return l.TradingFrozen
	}
	return false
}

// GetEffectiveLimits returns the active limits for a user (per-user override or system default).
func (g *Guard) GetEffectiveLimits(email string) UserLimits {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if l, ok := g.limits[strings.ToLower(email)]; ok {
		result := *l
		if result.MaxSingleOrderINR == 0 {
			result.MaxSingleOrderINR = SystemDefaults.MaxSingleOrderINR
		}
		if result.MaxOrdersPerDay == 0 {
			result.MaxOrdersPerDay = SystemDefaults.MaxOrdersPerDay
		}
		if result.MaxOrdersPerMinute == 0 {
			result.MaxOrdersPerMinute = SystemDefaults.MaxOrdersPerMinute
		}
		if result.DuplicateWindowSecs == 0 {
			result.DuplicateWindowSecs = SystemDefaults.DuplicateWindowSecs
		}
		if result.MaxDailyValueINR == 0 {
			result.MaxDailyValueINR = SystemDefaults.MaxDailyValueINR
		}
		return result
	}
	return SystemDefaults
}

// --- Internal check methods ---

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
	if req.Price <= 0 {
		return CheckResult{Allowed: true}
	}
	limits := g.GetEffectiveLimits(req.Email)
	value := float64(req.Quantity) * req.Price
	if value > limits.MaxSingleOrderINR {
		return CheckResult{
			Allowed: false, Reason: ReasonOrderValue,
			Message: fmt.Sprintf("Order value Rs %.0f exceeds limit Rs %.0f", value, limits.MaxSingleOrderINR),
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
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	g.maybeResetDay(t)
	if t.DailyOrderCount >= limits.MaxOrdersPerDay {
		return CheckResult{
			Allowed: false, Reason: ReasonDailyOrderLimit,
			Message: fmt.Sprintf("You have placed %d orders today (limit: %d). Resets at next market open.", t.DailyOrderCount, limits.MaxOrdersPerDay),
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
	if req.Price <= 0 {
		return CheckResult{Allowed: true} // MARKET orders — price unknown
	}
	limits := g.GetEffectiveLimits(email)
	orderValue := float64(req.Quantity) * req.Price

	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	g.maybeResetDay(t)

	if t.DailyPlacedValue+orderValue > limits.MaxDailyValueINR {
		return CheckResult{
			Allowed: false, Reason: ReasonDailyValueLimit,
			Message: fmt.Sprintf("Cumulative placed value Rs %.0f + this order Rs %.0f exceeds daily limit Rs %.0f",
				t.DailyPlacedValue, orderValue, limits.MaxDailyValueINR),
		}
	}
	return CheckResult{Allowed: true}
}

// --- Circuit Breaker ---

// recordRejection appends the current time to the user's recent rejections list.
func (g *Guard) recordRejection(email string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	t.RecentRejections = append(t.RecentRejections, time.Now())
}

// checkAutoFreeze checks if the user has accumulated enough recent rejections
// to trigger an automatic trading freeze. Returns true if the user was frozen.
func (g *Guard) checkAutoFreeze(email string) bool {
	limits := g.GetEffectiveLimits(email)
	if !limits.AutoFreezeOnLimitHit {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)

	// Prune rejections older than the window
	cutoff := time.Now().Add(-autoFreezeWindow)
	start := 0
	for start < len(t.RecentRejections) && t.RecentRejections[start].Before(cutoff) {
		start++
	}
	t.RecentRejections = t.RecentRejections[start:]

	if len(t.RecentRejections) >= autoFreezeThreshold {
		// Already frozen? Don't re-freeze.
		if l, ok := g.limits[email]; ok && l.TradingFrozen {
			return false
		}
		// Auto-freeze the user
		l := g.getOrCreateLimits(email)
		l.TradingFrozen = true
		l.FrozenBy = "riskguard:circuit-breaker"
		l.FrozenReason = "Automatic safety freeze: repeated limit violations"
		l.FrozenAt = time.Now()
		g.persistLimits(email, l)
		if g.logger != nil {
			g.logger.Warn("ADMIN ALERT: RiskGuard auto-froze user",
				"email", email,
				"reason", l.FrozenReason,
				"rejections_in_window", len(t.RecentRejections),
			)
		}
		// Notify admin (e.g. Telegram) asynchronously.
		if g.autoFreezeNotifier != nil {
			go g.autoFreezeNotifier(email, l.FrozenReason)
		}
		return true
	}
	return false
}

// UserStatus holds a snapshot of a user's current risk state for read-only reporting.
type UserStatus struct {
	DailyOrderCount  int       `json:"daily_order_count"`
	DailyPlacedValue float64   `json:"daily_placed_value"`
	IsFrozen         bool      `json:"is_frozen"`
	FrozenBy         string    `json:"frozen_by"`
	FrozenReason     string    `json:"frozen_reason"`
	FrozenAt         time.Time `json:"frozen_at,omitempty"`
}

// GetUserStatus returns a snapshot of the user's current daily order count, placed value, and freeze state.
func (g *Guard) GetUserStatus(email string) UserStatus {
	email = strings.ToLower(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	g.maybeResetDay(t)

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
	return status
}

// --- Helpers ---

func (g *Guard) getOrCreateTracker(email string) *UserTracker {
	t, ok := g.trackers[email]
	if !ok {
		t = &UserTracker{DayResetAt: time.Now()}
		g.trackers[email] = t
	}
	return t
}

func (g *Guard) getOrCreateLimits(email string) *UserLimits {
	l, ok := g.limits[email]
	if !ok {
		l = &UserLimits{
			AutoFreezeOnLimitHit:    SystemDefaults.AutoFreezeOnLimitHit,
			RequireConfirmAllOrders: SystemDefaults.RequireConfirmAllOrders,
		}
		g.limits[email] = l
	}
	return l
}

// maybeResetDay resets the daily counter if we've crossed 9:15 AM IST since last reset.
func (g *Guard) maybeResetDay(t *UserTracker) {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	now := g.clock().In(ist)
	resetTime := time.Date(now.Year(), now.Month(), now.Day(), 9, 15, 0, 0, ist)
	// If before 9:15 today, use yesterday's 9:15
	if now.Before(resetTime) {
		resetTime = resetTime.AddDate(0, 0, -1)
	}
	if t.DayResetAt.Before(resetTime) {
		t.DailyOrderCount = 0
		t.DailyPlacedValue = 0
		t.DayResetAt = now
	}
}

func (g *Guard) persistLimits(email string, l *UserLimits) {
	if g.db == nil {
		return
	}
	frozen := 0
	if l.TradingFrozen {
		frozen = 1
	}
	autoFreeze := 0
	if l.AutoFreezeOnLimitHit {
		autoFreeze = 1
	}
	requireConfirm := 0
	if l.RequireConfirmAllOrders {
		requireConfirm = 1
	}
	frozenAt := ""
	if !l.FrozenAt.IsZero() {
		frozenAt = l.FrozenAt.Format(time.RFC3339)
	}
	err := g.db.ExecInsert(
		`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET
		   max_single_order_inr=excluded.max_single_order_inr,
		   max_orders_per_day=excluded.max_orders_per_day,
		   max_orders_per_minute=excluded.max_orders_per_minute,
		   duplicate_window_secs=excluded.duplicate_window_secs,
		   max_daily_value_inr=excluded.max_daily_value_inr,
		   auto_freeze_on_limit_hit=excluded.auto_freeze_on_limit_hit,
		   require_confirm_all_orders=excluded.require_confirm_all_orders,
		   trading_frozen=excluded.trading_frozen,
		   frozen_at=excluded.frozen_at,
		   frozen_by=excluded.frozen_by,
		   frozen_reason=excluded.frozen_reason,
		   updated_at=excluded.updated_at`,
		email, l.MaxSingleOrderINR, l.MaxOrdersPerDay, l.MaxOrdersPerMinute, l.DuplicateWindowSecs, l.MaxDailyValueINR, autoFreeze, requireConfirm, frozen, frozenAt, l.FrozenBy, l.FrozenReason, time.Now().Format(time.RFC3339),
	)
	if err != nil && g.logger != nil {
		g.logger.Error("Failed to persist risk limits", "email", email, "error", err)
	}
}

// InitTable creates the risk_limits table if it doesn't exist, and migrates new columns.
//
// NOTE: the DEFAULT values below are the DB-side defaults used ONLY for rows
// that omit the column at INSERT time. persistLimits always supplies every
// column, so the authoritative Free-tier defaults are the Go-side SystemDefaults
// values above. The DDL defaults are kept aligned with SystemDefaults for
// consistency during forensic DB inspection.
func (g *Guard) InitTable() error {
	if g.db == nil {
		return nil
	}
	if err := g.db.ExecDDL(`
		CREATE TABLE IF NOT EXISTS risk_limits (
			email                      TEXT PRIMARY KEY,
			max_single_order_inr       REAL NOT NULL DEFAULT 50000,
			max_orders_per_day         INTEGER NOT NULL DEFAULT 20,
			max_orders_per_minute      INTEGER NOT NULL DEFAULT 10,
			duplicate_window_secs      INTEGER NOT NULL DEFAULT 30,
			max_daily_value_inr        REAL NOT NULL DEFAULT 200000,
			require_confirm_all_orders INTEGER NOT NULL DEFAULT 1,
			trading_frozen             INTEGER NOT NULL DEFAULT 0,
			frozen_at                  TEXT DEFAULT '',
			frozen_by                  TEXT DEFAULT '',
			frozen_reason              TEXT DEFAULT '',
			updated_at                 TEXT NOT NULL
		)`); err != nil {
		return err
	}
	// Migrate existing tables: add new columns if missing (ALTER TABLE is idempotent-safe with IF NOT EXISTS-style ignore).
	migrations := []string{
		`ALTER TABLE risk_limits ADD COLUMN max_orders_per_minute INTEGER NOT NULL DEFAULT 10`,
		`ALTER TABLE risk_limits ADD COLUMN duplicate_window_secs INTEGER NOT NULL DEFAULT 30`,
		`ALTER TABLE risk_limits ADD COLUMN max_daily_value_inr REAL NOT NULL DEFAULT 200000`,
		`ALTER TABLE risk_limits ADD COLUMN auto_freeze_on_limit_hit INTEGER NOT NULL DEFAULT 1`,
		// Secure-by-default: existing rows gain require_confirm_all_orders=1.
		`ALTER TABLE risk_limits ADD COLUMN require_confirm_all_orders INTEGER NOT NULL DEFAULT 1`,
	}
	for _, m := range migrations {
		_ = g.db.ExecDDL(m) // ignore "duplicate column" errors
	}
	return nil
}

// LoadLimits loads per-user limits from the database into memory.
func (g *Guard) LoadLimits() error {
	if g.db == nil {
		return nil
	}
	rows, err := g.db.RawQuery(`SELECT email, max_single_order_inr, max_orders_per_day, max_orders_per_minute, duplicate_window_secs, max_daily_value_inr, auto_freeze_on_limit_hit, require_confirm_all_orders, trading_frozen, frozen_at, frozen_by, frozen_reason FROM risk_limits`)
	if err != nil {
		return fmt.Errorf("load risk_limits: %w", err)
	}
	defer rows.Close()

	g.mu.Lock()
	defer g.mu.Unlock()

	for rows.Next() {
		var email, frozenAt, frozenBy, frozenReason string
		var maxOrder, maxDailyValue float64
		var maxDaily, maxPerMin, dupWindow, autoFreeze, requireConfirm, frozen int
		if err := rows.Scan(&email, &maxOrder, &maxDaily, &maxPerMin, &dupWindow, &maxDailyValue, &autoFreeze, &requireConfirm, &frozen, &frozenAt, &frozenBy, &frozenReason); err != nil {
			return fmt.Errorf("scan risk_limits: %w", err)
		}
		l := &UserLimits{
			MaxSingleOrderINR:       maxOrder,
			MaxOrdersPerDay:         maxDaily,
			MaxOrdersPerMinute:      maxPerMin,
			DuplicateWindowSecs:     dupWindow,
			MaxDailyValueINR:        maxDailyValue,
			AutoFreezeOnLimitHit:    autoFreeze != 0,
			RequireConfirmAllOrders: requireConfirm != 0,
			TradingFrozen:           frozen != 0,
			FrozenBy:                frozenBy,
			FrozenReason:            frozenReason,
		}
		if frozenAt != "" {
			l.FrozenAt, _ = time.Parse(time.RFC3339, frozenAt)
		}
		g.limits[strings.ToLower(email)] = l
	}
	return rows.Err()
}
