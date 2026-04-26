package riskguard

import (
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// lifecycle.go — freeze lifecycle (per-user + global) and the auto-freeze
// circuit breaker. The "stop trading RIGHT NOW" surface lives in one
// focused file so operators (and the breaker) have a single audit target
// during incidents. Extracted from guard.go in the 2026-04 cohesion split.
//
// Pure file move — no behavior change.

// GlobalFreezeStatus holds the current global freeze state with metadata.
type GlobalFreezeStatus struct {
	IsFrozen bool      `json:"is_frozen"`
	FrozenBy string    `json:"frozen_by,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	FrozenAt time.Time `json:"frozen_at,omitempty"`
}

// FreezeGlobal activates a server-wide trading freeze that blocks ALL users.
//
// Emits RiskguardKillSwitchTrippedEvent (Active=true) on a real off→on
// transition. Idempotent re-emission: a second FreezeGlobal call while
// already frozen is a no-op and emits no event, so projection replays
// see one trip per actual lifecycle. The dispatcher field is read under
// the same writer-lock that mutates the freeze state, then the actual
// Dispatch happens after the lock is released to avoid handlers running
// under the riskguard mutex.
func (g *Guard) FreezeGlobal(frozenBy, reason string) {
	g.mu.Lock()
	wasFrozen := g.globalFrozen
	g.globalFrozen = true
	g.globalFrozenBy = frozenBy
	g.globalFrozenReason = reason
	g.globalFrozenAt = time.Now()
	dispatcher := g.events
	g.mu.Unlock()
	if g.logger != nil {
		g.logger.Warn("GLOBAL TRADING FREEZE ACTIVATED", "by", frozenBy, "reason", reason)
	}
	if !wasFrozen && dispatcher != nil {
		dispatcher.Dispatch(domain.RiskguardKillSwitchTrippedEvent{
			FrozenBy:  frozenBy,
			Reason:    reason,
			Active:    true,
			Timestamp: time.Now().UTC(),
		})
	}
}

// UnfreezeGlobal lifts the server-wide trading freeze.
//
// Emits RiskguardKillSwitchTrippedEvent (Active=false) on a real on→off
// transition. Idempotent: unfreeze when already unfrozen is a no-op and
// emits no event.
func (g *Guard) UnfreezeGlobal() {
	g.mu.Lock()
	wasFrozen := g.globalFrozen
	g.globalFrozen = false
	g.globalFrozenBy = ""
	g.globalFrozenReason = ""
	g.globalFrozenAt = time.Time{}
	dispatcher := g.events
	g.mu.Unlock()
	if g.logger != nil {
		g.logger.Info("Global trading freeze lifted")
	}
	if wasFrozen && dispatcher != nil {
		dispatcher.Dispatch(domain.RiskguardKillSwitchTrippedEvent{
			Active:    false,
			Timestamp: time.Now().UTC(),
		})
	}
}

// IsGloballyFrozen returns true if the server-wide trading freeze is active.
func (g *Guard) IsGloballyFrozen() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.globalFrozen
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

// --- Circuit Breaker ---

// dispatchDailyResetIfNeeded is the centralised emit-helper for the
// trading-day rollover event. Callers that observed a true return from
// maybeResetDay AFTER releasing g.mu pass the captured dispatcher (under
// the lock) and let this function handle the nil-checks and event
// construction. Keeping this in one place means future event-shape
// changes touch one site, not three.
func (g *Guard) dispatchDailyResetIfNeeded(email string, didReset bool, dispatcher *domain.EventDispatcher) {
	if !didReset || dispatcher == nil {
		return
	}
	dispatcher.Dispatch(domain.RiskguardDailyCounterResetEvent{
		UserEmail: email,
		Reason:    "trading_day_boundary",
		Timestamp: time.Now().UTC(),
	})
}

// recordRejection appends the current time to the user's recent rejections list.
//
// Emits RiskguardRejectionEvent capturing the counter mutation. Distinct
// from the use-case-layer RiskLimitBreachedEvent (which records that an
// ORDER was blocked); this event records that the COUNTER was bumped, so
// the counters aggregate stream can reconstruct the auto-freeze sliding
// window without joining against the order pipeline. Reason is the
// RejectionReason that drove the call, threaded through from CheckOrder
// for downstream projector aggregation by reason. The event is dispatched
// after the lock is released so handlers don't run under riskguard's mutex.
func (g *Guard) recordRejection(email string, reason RejectionReason) {
	g.mu.Lock()
	t := g.getOrCreateTracker(email)
	t.RecentRejections = append(t.RecentRejections, time.Now())
	dispatcher := g.events
	g.mu.Unlock()
	if dispatcher != nil {
		dispatcher.Dispatch(domain.RiskguardRejectionEvent{
			UserEmail: email,
			Reason:    string(reason),
			Timestamp: time.Now().UTC(),
		})
	}
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
