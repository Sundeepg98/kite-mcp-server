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
	// ReasonAnomalyHigh fires when an order is simultaneously > μ+3σ AND
	// > 10×μ on the user's rolling 30-day baseline. Catches the "user who
	// typically places Rs 5k orders suddenly places Rs 49k" pattern that
	// slips under static per-order caps but is statistically impossible
	// given their trading history — prompt injection or account takeover.
	ReasonAnomalyHigh RejectionReason = "anomaly_high"
	// ReasonOffHoursBlocked fires on any order placed between 02:00 and 06:00
	// IST. Outside market hours AND outside the typical human decision window,
	// so any activity there is either automation gone wrong or an adversary
	// betting the account owner is asleep. Power users can opt out via
	// UserLimits.AllowOffHours.
	ReasonOffHoursBlocked RejectionReason = "off_hours_blocked"
)

// Anomaly-detection tuning constants. Centralised here so the product team
// can audit the thresholds without hunting through the check function.
const (
	// anomalySigmaMultiplier is how many standard deviations above the mean
	// an order must sit before it is a statistical outlier (3σ ≈ 0.27% of a
	// normal distribution's mass — deliberately conservative).
	anomalySigmaMultiplier = 3.0
	// anomalyMeanMultiplier is the multiplicative cap: even a 3σ event is
	// tolerated unless it also exceeds 10× the user's historical mean. This
	// prevents false positives for users whose stdev is naturally tiny
	// (e.g. only ever trades exactly Rs 5000 lots — stdev ~= 0, so every
	// non-baseline order is "infinite σ" away).
	anomalyMeanMultiplier = 10.0
	// anomalyBaselineDays is the rolling window over which we compute the
	// user's baseline. 30 days covers 20-ish trading days — long enough to
	// smooth out one-off fat-finger days, short enough to adapt as the
	// user's habits evolve.
	anomalyBaselineDays = 30
	// offHoursStartIST and offHoursEndIST define the hard-block window in
	// IST [start, end). 02:00–06:00 is after late-night manual trading has
	// wound down and before the market-prep hours when legitimate automation
	// (morning brief jobs, SIP triggers) kicks in.
	offHoursStartIST = 2
	offHoursEndIST   = 6
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

// UserLimits lives in limits.go (2026-04 cohesion split). See that file
// for the struct definition, Set* hooks, GetEffectiveLimits resolution,
// and SQLite persistence (InitTable, LoadLimits, persistLimits).

// recentOrder + UserTracker live in trackers.go (2026-04 cohesion split).
// GetUserStatus, getOrCreateTracker, maybeResetDay, and UserStatus also
// live there since they operate on the same per-user in-memory state.

// FreezeQuantityLookup is an interface for looking up instrument freeze quantities.
// Implemented by instruments.Manager wrapper to avoid direct dependency.
type FreezeQuantityLookup interface {
	GetFreezeQuantity(exchange, tradingsymbol string) (uint32, bool)
}

// BaselineProvider returns rolling order-value statistics for a user. The
// production implementation is audit.Store.UserOrderStats, which queries
// the tool_calls table for historical place_order/modify_order rows and
// computes mean + population-stdev over the window. This interface lets
// tests inject fakes without pulling in the audit package (which would
// create a circular dependency) and keeps riskguard narrowly dependent
// on the one method it needs.
//
// Contract: when the user has fewer than the store's minimum history
// threshold (currently 5 rows), the provider MUST return (0, 0, count)
// so the guard knows to skip the anomaly check rather than treat the
// empty baseline as "all orders are infinitely anomalous".
type BaselineProvider interface {
	UserOrderStats(email string, days int) (mean, stdev, count float64)
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
	baseline            BaselineProvider // optional — nil ⇒ anomaly check is a no-op
	db                  *alerts.DB
	logger              *slog.Logger
	autoFreezeNotifier  AutoFreezeNotifier
	clock               func() time.Time // defaults to time.Now
	// dedup tracks user-supplied client_order_id idempotency keys. Complements
	// the time-based duplicate detection in checkDuplicateOrder — this one
	// triggers on an explicit user-supplied key, so mcp-remote retries after
	// 504 reuse the same key and are rejected deterministically.
	dedup *Dedup
	// perSecond enforces SEBI's Apr 2026 retail-algo sub-second threshold
	// defensively: capped at 9/sec so the broker-side 10/sec cap always has
	// a 1-order headroom. Keyed by (email, calendar_second) — see per_second.go.
	perSecond *perSecondCounter
	// Global trading freeze — blocks ALL users from placing orders.
	globalFrozen   bool
	globalFrozenBy string
	globalFrozenAt     time.Time
	globalFrozenReason string
	// checks is the ordered chain evaluated by CheckOrder. Built-ins are
	// pre-registered by NewGuard; plugins add rules via RegisterCheck. The
	// slice is kept sorted by Check.Order() ascending so iteration preserves
	// evaluation order. Guarded by mu (writer-lock on RegisterCheck; reader
	// snapshot on CheckOrder).
	checks []Check
}

// NewGuard creates a new Guard with system defaults. All built-in risk
// checks (kill switch, confirmation, order-value, quantity, daily count,
// per-second rate, per-minute rate, idempotency-key dup, time-based dup,
// daily value, anomaly, off-hours) are pre-registered in their canonical
// order — see check.go for the stable Order() constants and the
// builtinChecks() list. Additional checks can be wired via
// Guard.RegisterCheck before the guard sees its first order.
func NewGuard(logger *slog.Logger) *Guard {
	g := &Guard{
		trackers:  make(map[string]*UserTracker),
		limits:    make(map[string]*UserLimits),
		logger:    logger,
		clock:     time.Now,
		dedup:     NewDedup(DefaultDedupTTL),
		perSecond: newPerSecondCounter(),
	}
	for _, c := range builtinChecks(g) {
		g.insertCheckLocked(c)
	}
	return g
}

// RegisterCheck installs a Check into the ordered chain. Safe to call
// concurrently with CheckOrder — the writer locks mu, and the reader
// path takes a snapshot under a reader-lock. Duplicate Name() values
// are allowed (last-registered wins at its Order position) but not
// encouraged; use distinct snake_case names to keep logs searchable.
//
// Typical usage: called once during app wiring, before the MCP server
// accepts its first tool call. Plugins that want to add a check
// dynamically (e.g. per-user) should still register at startup and
// gate inside Evaluate() on req.Email.
func (g *Guard) RegisterCheck(c Check) {
	if c == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.insertCheckLocked(c)
}

// insertCheckLocked appends c to g.checks and re-sorts by Order ascending.
// Caller must hold g.mu.
//
// Sort stability matters: when two checks share the same Order() value,
// the later-registered one runs after the earlier one. This keeps
// registration order as a secondary tiebreaker, which is what users
// expect ("my third custom check at 650 runs after my first custom
// check at 650").
func (g *Guard) insertCheckLocked(c Check) {
	g.checks = append(g.checks, c)
	// Insertion-sort bubble: walk backward swapping while the previous
	// check has a strictly greater Order(). This is O(n) per insert,
	// O(n²) overall — fine for the ~12 built-ins + handful of plugins.
	// (A full sort.SliceStable would also work; this is simpler.)
	for i := len(g.checks) - 1; i > 0; i-- {
		if g.checks[i-1].Order() > g.checks[i].Order() {
			g.checks[i-1], g.checks[i] = g.checks[i], g.checks[i-1]
			continue
		}
		break
	}
}

// ListCheckNames returns the Name() of every registered check in
// evaluation order. Intended for admin tooling ("show me the active
// risk chain"), audit, and tests. Snapshot: safe for concurrent use
// with RegisterCheck, but the returned slice is a copy.
func (g *Guard) ListCheckNames() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	names := make([]string, len(g.checks))
	for i, c := range g.checks {
		names[i] = c.Name()
	}
	return names
}

// snapshotChecks returns a copy of the current check chain under a reader
// lock. Used by CheckOrder to evaluate without holding the lock across
// per-check evaluation (checks may take the writer-lock themselves for
// tracker bookkeeping, so CheckOrder must not hold it).
func (g *Guard) snapshotChecks() []Check {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Check, len(g.checks))
	copy(out, g.checks)
	return out
}

// Set* hooks (SetClock, SetDB, SetFreezeQuantityLookup, SetBaselineProvider,
// SetAutoFreezeNotifier) live in limits.go alongside the persistence layer
// they configure.

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

// CheckOrder evaluates the registered check chain in Order ascending.
// The first Check returning Allowed=false wins and short-circuits.
//
// Built-in rule precedence (see Order* constants in check.go):
//   100  kill_switch                (policy — no auto-freeze)
//   200  confirmation_required      (policy — no auto-freeze)
//   300  order_value                (limit)
//   400  quantity_limit             (limit)
//   500  daily_order_count          (limit)
//   600  per_second_rate            (limit — SEBI Apr 2026 defence)
//   700  rate_limit                 (limit — per-minute)
//   800  client_order_id_duplicate  (limit — idempotency key)
//   900  duplicate_order            (limit — time-based params hash)
//  1000  daily_value                (limit)
//  1100  anomaly_multiplier         (limit — rolling baseline)
//  1200  off_hours                  (limit — 02:00–06:00 IST)
//
// Global freeze is evaluated BEFORE the chain because it blocks every
// user unconditionally and precedes any per-user check.
//
// For any Check whose RecordOnRejection()==true, a rejection is logged
// to the user's recent-rejections sliding window; three such rejections
// within autoFreezeWindow trigger an auto-freeze. Policy checks (kill
// switch, confirmation gate) return false so they don't drive a user
// toward a lockout for an error they didn't make.
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

	// Snapshot the chain so per-check calls that themselves take g.mu
	// (tracker bookkeeping) do not deadlock against a writer.
	for _, c := range g.snapshotChecks() {
		r := safeEvaluate(g.logger, c, req)
		if r.Allowed {
			continue
		}
		if c.RecordOnRejection() {
			g.recordRejection(email)
			if frozen := g.checkAutoFreeze(email); frozen {
				r.Message += " [Account auto-frozen due to repeated violations]"
			}
		}
		return r
	}
	return CheckResult{Allowed: true}
}

// safeEvaluate runs Check.Evaluate with panic recovery. A panicking
// custom check is treated as a REJECTION (fail-closed) so a buggy
// plugin cannot silently wave bad orders through. The panic is logged
// and recorded with ReasonAutoFreeze-adjacent semantics:
// Allowed=false, Reason="check_panic", Message containing the check
// name and panic value. Built-in checks never panic in practice
// (their bodies are deterministic arithmetic on UserLimits), so this
// net is almost exclusively for third-party / user-written checks.
//
// Why fail-closed not fail-open: the riskguard layer is the last
// defence before an order hits the broker. Letting a buggy plugin
// silently allow the order is a worse outcome than falsely
// rejecting one — a rejected order can be retried; a placed order
// carries financial consequences.
func safeEvaluate(logger *slog.Logger, c Check, req OrderCheckRequest) (result CheckResult) {
	defer func() {
		if r := recover(); r != nil {
			name := "<nil>"
			if c != nil {
				name = c.Name()
			}
			if logger != nil {
				logger.Error("riskguard: Check.Evaluate panicked",
					"check", name, "panic", r)
			}
			result = CheckResult{
				Allowed: false,
				Reason:  "check_panic",
				Message: fmt.Sprintf("risk check %q panicked: %v", name, r),
			}
		}
	}()
	return c.Evaluate(req)
}

// lowerEmail normalises the caller email to lowercase for lookup paths
// shared by the Check adapters in check.go. Kept in guard.go because the
// adapters are the only callers and the function is a one-liner; moving
// it to a util file would be premature abstraction.
func lowerEmail(email string) string { return strings.ToLower(email) }

// RecordOrder records a successful order for all tracking: daily count, rate window, duplicate detection, and daily value.
func (g *Guard) RecordOrder(email string, req ...OrderCheckRequest) {
	email = strings.ToLower(email)
	// Bump the per-calendar-second counter first — it has its own mutex and
	// uses the guard's clock, so the (email, second) bucket reflects the
	// same "now" the CheckOrder path sees.
	g.recordPerSecondOrder(email)
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

// GetEffectiveLimits lives in limits.go (merges per-user overrides with
// SystemDefaults; used by every check in the pipeline below).

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
	if req.Price <= 0 {
		return CheckResult{Allowed: true} // MARKET — skip
	}
	orderValue := float64(req.Quantity) * req.Price
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

// --- Helpers ---

// getOrCreateLimits + persistLimits + InitTable + LoadLimits all live in
// limits.go alongside UserLimits (2026-04 cohesion split).

// persistLimits, InitTable, LoadLimits all live in limits.go alongside
// UserLimits (2026-04 cohesion split).
