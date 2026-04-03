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
var SystemDefaults = UserLimits{
	MaxSingleOrderINR: 500000, // Rs 5,00,000
	MaxOrdersPerDay:   200,
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
	ReasonTradingFrozen   RejectionReason = "trading_frozen"
	ReasonOrderValue      RejectionReason = "order_value_limit"
	ReasonQuantityLimit   RejectionReason = "quantity_limit"
	ReasonDailyOrderLimit RejectionReason = "daily_order_limit"
)

// CheckResult is returned by the guard for every order attempt.
type CheckResult struct {
	Allowed bool
	Reason  RejectionReason
	Message string
}

// UserLimits holds configurable limits for a user.
type UserLimits struct {
	MaxSingleOrderINR float64
	MaxOrdersPerDay   int
	TradingFrozen     bool
	FrozenBy          string
	FrozenReason      string
	FrozenAt          time.Time
}

// UserTracker holds in-memory per-user trading state.
type UserTracker struct {
	DailyOrderCount int
	DayResetAt      time.Time
}

// FreezeQuantityLookup is an interface for looking up instrument freeze quantities.
// Implemented by instruments.Manager wrapper to avoid direct dependency.
type FreezeQuantityLookup interface {
	GetFreezeQuantity(exchange, tradingsymbol string) (uint32, bool)
}

// Guard is the central risk management engine.
type Guard struct {
	mu           sync.RWMutex
	trackers     map[string]*UserTracker
	limits       map[string]*UserLimits // per-user overrides
	freezeLookup FreezeQuantityLookup
	db           *alerts.DB
	logger       *slog.Logger
}

// NewGuard creates a new Guard with system defaults.
func NewGuard(logger *slog.Logger) *Guard {
	return &Guard{
		trackers: make(map[string]*UserTracker),
		limits:   make(map[string]*UserLimits),
		logger:   logger,
	}
}

// SetDB sets the SQLite database for persisting risk limits.
func (g *Guard) SetDB(db *alerts.DB) { g.db = db }

// SetFreezeQuantityLookup sets the instrument lookup for quantity checks.
func (g *Guard) SetFreezeQuantityLookup(lookup FreezeQuantityLookup) { g.freezeLookup = lookup }

// OrderCheckRequest contains the data needed to evaluate an order.
type OrderCheckRequest struct {
	Email         string
	ToolName      string
	Exchange      string
	Tradingsymbol string
	Quantity      int
	Price         float64 // 0 for MARKET orders
	OrderType     string  // MARKET, LIMIT, SL, SL-M
}

// CheckOrder runs all safety checks in sequence. Returns on first failure.
func (g *Guard) CheckOrder(req OrderCheckRequest) CheckResult {
	email := strings.ToLower(req.Email)

	// 1. Kill switch
	if r := g.checkKillSwitch(email); !r.Allowed {
		return r
	}
	// 2. Order value
	if r := g.checkOrderValue(req); !r.Allowed {
		return r
	}
	// 3. Quantity limit
	if r := g.checkQuantityLimit(req); !r.Allowed {
		return r
	}
	// 4. Daily order count
	if r := g.checkDailyOrderCount(email); !r.Allowed {
		return r
	}

	return CheckResult{Allowed: true}
}

// RecordOrder increments the daily order count after a successful placement.
func (g *Guard) RecordOrder(email string) {
	email = strings.ToLower(email)
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.getOrCreateTracker(email)
	g.maybeResetDay(t)
	t.DailyOrderCount++
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
	if uint32(req.Quantity) > freezeQty {
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
		l = &UserLimits{}
		g.limits[email] = l
	}
	return l
}

// maybeResetDay resets the daily counter if we've crossed 9:15 AM IST since last reset.
func (g *Guard) maybeResetDay(t *UserTracker) {
	ist, _ := time.LoadLocation("Asia/Kolkata")
	now := time.Now().In(ist)
	resetTime := time.Date(now.Year(), now.Month(), now.Day(), 9, 15, 0, 0, ist)
	// If before 9:15 today, use yesterday's 9:15
	if now.Before(resetTime) {
		resetTime = resetTime.AddDate(0, 0, -1)
	}
	if t.DayResetAt.Before(resetTime) {
		t.DailyOrderCount = 0
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
	frozenAt := ""
	if !l.FrozenAt.IsZero() {
		frozenAt = l.FrozenAt.Format(time.RFC3339)
	}
	err := g.db.ExecInsert(
		`INSERT INTO risk_limits (email, max_single_order_inr, max_orders_per_day, trading_frozen, frozen_at, frozen_by, frozen_reason, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET
		   max_single_order_inr=excluded.max_single_order_inr,
		   max_orders_per_day=excluded.max_orders_per_day,
		   trading_frozen=excluded.trading_frozen,
		   frozen_at=excluded.frozen_at,
		   frozen_by=excluded.frozen_by,
		   frozen_reason=excluded.frozen_reason,
		   updated_at=excluded.updated_at`,
		email, l.MaxSingleOrderINR, l.MaxOrdersPerDay, frozen, frozenAt, l.FrozenBy, l.FrozenReason, time.Now().Format(time.RFC3339),
	)
	if err != nil && g.logger != nil {
		g.logger.Error("Failed to persist risk limits", "email", email, "error", err)
	}
}

// InitTable creates the risk_limits table if it doesn't exist.
func (g *Guard) InitTable() error {
	if g.db == nil {
		return nil
	}
	return g.db.ExecDDL(`
		CREATE TABLE IF NOT EXISTS risk_limits (
			email                TEXT PRIMARY KEY,
			max_single_order_inr REAL NOT NULL DEFAULT 500000,
			max_orders_per_day   INTEGER NOT NULL DEFAULT 200,
			trading_frozen       INTEGER NOT NULL DEFAULT 0,
			frozen_at            TEXT DEFAULT '',
			frozen_by            TEXT DEFAULT '',
			frozen_reason        TEXT DEFAULT '',
			updated_at           TEXT NOT NULL
		)`)
}

// LoadLimits loads per-user limits from the database into memory.
func (g *Guard) LoadLimits() error {
	if g.db == nil {
		return nil
	}
	rows, err := g.db.RawQuery(`SELECT email, max_single_order_inr, max_orders_per_day, trading_frozen, frozen_at, frozen_by, frozen_reason FROM risk_limits`)
	if err != nil {
		return fmt.Errorf("load risk_limits: %w", err)
	}
	defer rows.Close()

	g.mu.Lock()
	defer g.mu.Unlock()

	for rows.Next() {
		var email, frozenAt, frozenBy, frozenReason string
		var maxOrder float64
		var maxDaily, frozen int
		if err := rows.Scan(&email, &maxOrder, &maxDaily, &frozen, &frozenAt, &frozenBy, &frozenReason); err != nil {
			return fmt.Errorf("scan risk_limits: %w", err)
		}
		l := &UserLimits{
			MaxSingleOrderINR: maxOrder,
			MaxOrdersPerDay:   maxDaily,
			TradingFrozen:     frozen != 0,
			FrozenBy:          frozenBy,
			FrozenReason:      frozenReason,
		}
		if frozenAt != "" {
			l.FrozenAt, _ = time.Parse(time.RFC3339, frozenAt)
		}
		g.limits[strings.ToLower(email)] = l
	}
	return rows.Err()
}
