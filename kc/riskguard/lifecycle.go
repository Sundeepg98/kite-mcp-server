package riskguard

import (
	"strings"
	"time"
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
