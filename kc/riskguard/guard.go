package riskguard

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
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
	// ReasonOTRBand fires when the order's price is outside the SEBI
	// OTR exemption band around LTP. ±0.75% for cash + futures, ±40%
	// for equity options (SEBI circular Feb 2026, effective Apr 6 2026).
	// Catches fat-finger trades and keeps the user's OTR ratio clean
	// without depending on the broker side throttling.
	ReasonOTRBand RejectionReason = "otr_band_violation"
	// ReasonCircuitBreached fires when the order's LIMIT price is
	// outside the exchange-set daily circuit band (typically ±5/10/20%
	// of previous-day close). Pre-T2 we relied on Kite to surface this;
	// catching it client-side avoids a round trip + per-second rate
	// pressure for a guaranteed-rejection.
	ReasonCircuitBreached RejectionReason = "circuit_breached"
	// ReasonInsufficientMargin fires when the optional pre-trade
	// margin check (T5) computes notional > available. NOT a fat-
	// finger or abuse signal — a legitimate margin exhaustion from
	// prior fills produces this. RecordOnRejection=false on the
	// check so it doesn't trigger auto-freeze.
	ReasonInsufficientMargin RejectionReason = "insufficient_margin"
	// ReasonMarketClosed fires on any non-AMO order placed outside
	// NSE/BSE equity-cash market hours (weekdays, [09:15, 15:30) IST).
	// Variety="amo" bypasses the check (next-session queue). T1 in the
	// gap catalogue. Holiday calendar is intentionally NOT enforced
	// client-side — Kite's OMS rejects holiday orders anyway, and
	// shipping a stale calendar would create false-rejects on every
	// SEBI-announced special session.
	ReasonMarketClosed RejectionReason = "market_closed"
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
	ltpLookup           LTPLookup        // SEBI OTR band oracle; nil ⇒ band check is a no-op
	circuitLookup       CircuitLookup    // exchange circuit-band oracle; nil ⇒ circuit check is a no-op
	marginLookup        MarginLookup     // available-margin oracle for the T5 pre-trade check
	marginCheckEnabled  bool             // T5: opt-in flag; default false
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
	// events is the optional domain event dispatcher. When non-nil, the
	// counters aggregate's mutation surface (FreezeGlobal kill-switch
	// trip/lift, maybeResetDay daily-counter reset, recordRejection
	// rejection-window increment) emits typed Riskguard*Event values so
	// the stream can be replayed by a future read-side projector. Nil-safe
	// throughout: a Guard constructed without SetEventDispatcher behaves
	// identically to the pre-ES code path. Mutated only via
	// SetEventDispatcher (which acquires mu); read paths take a snapshot
	// under the existing locks already held at the call site.
	events *domain.EventDispatcher
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

// Freeze/Unfreeze/IsFrozen (per-user) + FreezeGlobal/UnfreezeGlobal/
// IsGloballyFrozen/GetGlobalFreezeStatus/GlobalFreezeStatus + circuit
// breaker (recordRejection, checkAutoFreeze) all live in lifecycle.go.

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
	// Variety is the Kite order variety (regular/amo/co/iceberg/auction).
	// Currently consulted only by checkMarketHours: variety="amo" bypasses
	// the [09:15, 15:30) IST market-hours block because AMO orders are
	// queued for the next session by Kite's OMS. Empty defaults to
	// "regular" semantics (i.e. NOT an AMO bypass).
	Variety string
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
			g.recordRejection(email, r.Reason)
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
//
// When maybeResetDay rolls the trading-day boundary (DayResetAt < today's
// 9:15 IST), a RiskguardDailyCounterResetEvent is dispatched AFTER the
// lock is released so handlers don't run under the riskguard mutex —
// dispatcher captured under the writer-lock for snapshot consistency.
func (g *Guard) RecordOrder(email string, req ...OrderCheckRequest) {
	email = strings.ToLower(email)
	// Bump the per-calendar-second counter first — it has its own mutex and
	// uses the guard's clock, so the (email, second) bucket reflects the
	// same "now" the CheckOrder path sees.
	g.recordPerSecondOrder(email)
	g.mu.Lock()
	t := g.getOrCreateTracker(email)
	didReset := g.maybeResetDay(t)
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
	dispatcher := g.events
	g.mu.Unlock()
	g.dispatchDailyResetIfNeeded(email, didReset, dispatcher)
}

// GetEffectiveLimits lives in limits.go (merges per-user overrides with
// SystemDefaults; used by every check in the pipeline below).

// --- Internal check methods ---
// The 10+ checkXxx() methods that each built-in Check adapter in check.go
// calls into live in internal_checks.go (2026-04 cohesion split).

// --- Helpers ---
// getOrCreateLimits + persistLimits + InitTable + LoadLimits all live in
// limits.go alongside UserLimits (2026-04 cohesion split).
