package riskguard

import (
	"fmt"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// limits.go — UserLimits type + per-collaborator Set* hooks +
// effective-limits resolution + SQLite persistence (InitTable, LoadLimits,
// persistLimits). Extracted from guard.go in the 2026-04 cohesion split
// so the configuration/persistence concern lives in one focused file.
//
// Pure file move — no behavior change.

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
	// AllowOffHours, when true, lets this user trade during the 02:00–06:00
	// IST hard-block window. Default false for all new accounts — opt-in
	// escape hatch for power users running legitimate overnight automation.
	AllowOffHours bool
	TradingFrozen bool
	FrozenBy      string
	FrozenReason  string
	FrozenAt      time.Time
}

// --- Per-collaborator Set* hooks --------------------------------------------

// SetClock overrides the time source (for testing).
func (g *Guard) SetClock(c func() time.Time) { g.clock = c }

// SetDB sets the SQLite database for persisting risk limits.
func (g *Guard) SetDB(db *alerts.DB) { g.db = db }

// SetFreezeQuantityLookup sets the instrument lookup for quantity checks.
func (g *Guard) SetFreezeQuantityLookup(lookup FreezeQuantityLookup) { g.freezeLookup = lookup }

// SetBaselineProvider wires the rolling-baseline source used by the anomaly
// check. Optional: when nil, checkAnomalyMultiplier is a silent no-op, which
// is the correct behaviour for DevMode / tests without an audit store.
func (g *Guard) SetBaselineProvider(p BaselineProvider) { g.baseline = p }

// SetAutoFreezeNotifier registers a callback invoked when the circuit breaker
// auto-freezes a user. The callback receives the user email and the freeze reason.
func (g *Guard) SetAutoFreezeNotifier(fn AutoFreezeNotifier) { g.autoFreezeNotifier = fn }

// --- Effective-limits resolution ------------------------------------------

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

// getOrCreateLimits returns the per-email limits, creating a defaults-filled
// record on demand. Caller must hold g.mu (writer).
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

// --- SQLite persistence ----------------------------------------------------

// persistLimits upserts the current in-memory UserLimits for email into the
// risk_limits table. No-op when g.db is nil (in-memory mode).
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

// InitTable creates the risk_limits table if it doesn't exist, and migrates
// new columns.
//
// NOTE: the DEFAULT values below are the DB-side defaults used ONLY for rows
// that omit the column at INSERT time. persistLimits always supplies every
// column, so the authoritative Free-tier defaults are the Go-side
// SystemDefaults values in guard.go. The DDL defaults are kept aligned with
// SystemDefaults for consistency during forensic DB inspection.
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
	// Migrate existing tables: add new columns if missing (ALTER TABLE is
	// idempotent-safe with IF NOT EXISTS-style ignore).
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
