package riskguard

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// limits_money_test.go — Money-VO behavior of UserLimits. Pinned
// invariants for Slice 1 of the Money sweep:
//   - Max*INR fields are typed Money (currency-aware, not bare float64)
//   - Zero-value Money on a per-user override falls back to SystemDefaults
//     in GetEffectiveLimits (the "no per-user override" sentinel)
//   - SystemDefaults values are denominated in INR (sanity check that
//     the Free-tier numbers didn't get swapped for a different currency)

// TestUserLimits_MaxFieldsAreMoney is the type-level assertion: if either
// Max*INR field reverts to a primitive, this stops compiling rather than
// producing a silently-wrong currency comparison at runtime.
func TestUserLimits_MaxFieldsAreMoney(t *testing.T) {
	t.Parallel()
	var l UserLimits
	// Compile-time assertion: assignment requires domain.Money on both sides.
	l.MaxSingleOrderINR = domain.NewINR(123)
	l.MaxDailyValueINR = domain.NewINR(456)
	assert.Equal(t, "INR", l.MaxSingleOrderINR.Currency)
	assert.Equal(t, "INR", l.MaxDailyValueINR.Currency)
	assert.Equal(t, float64(123), l.MaxSingleOrderINR.Float64())
	assert.Equal(t, float64(456), l.MaxDailyValueINR.Float64())
}

// TestSystemDefaults_AreINR — the Free-tier defaults must be denominated
// in INR or the entire enforcement engine compares apples to oranges.
func TestSystemDefaults_AreINR(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "INR", SystemDefaults.MaxSingleOrderINR.Currency)
	assert.Equal(t, "INR", SystemDefaults.MaxDailyValueINR.Currency)
	assert.Equal(t, float64(50000), SystemDefaults.MaxSingleOrderINR.Float64())
	assert.Equal(t, float64(200000), SystemDefaults.MaxDailyValueINR.Float64())
}

// TestGetEffectiveLimits_ZeroMoneyFallsBackToDefault verifies the
// "no per-user override" sentinel: a zero Money on the per-user record
// must be replaced by the SystemDefaults value, exactly as zero-float64
// did before. This is the sentinel check that getOrCreateLimits relies
// on (it constructs UserLimits with zero-value money fields and lets
// GetEffectiveLimits backfill).
func TestGetEffectiveLimits_ZeroMoneyFallsBackToDefault(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())

	g.mu.Lock()
	g.limits["zero@test.com"] = &UserLimits{
		// MaxSingleOrderINR and MaxDailyValueINR left as zero Money
		MaxOrdersPerDay: 50, // unrelated non-zero override
	}
	g.mu.Unlock()

	l := g.GetEffectiveLimits("zero@test.com")
	assert.True(t, l.MaxSingleOrderINR.Float64() == SystemDefaults.MaxSingleOrderINR.Float64(),
		"zero Money should fall back to SystemDefaults for MaxSingleOrderINR")
	assert.True(t, l.MaxDailyValueINR.Float64() == SystemDefaults.MaxDailyValueINR.Float64(),
		"zero Money should fall back to SystemDefaults for MaxDailyValueINR")
	assert.Equal(t, 50, l.MaxOrdersPerDay, "non-zero override preserved")
}

// TestGetEffectiveLimits_NonZeroMoneyPreserved — the per-user override
// path. When the user's record carries a positive Money value, that
// value (not SystemDefaults) wins.
func TestGetEffectiveLimits_NonZeroMoneyPreserved(t *testing.T) {
	t.Parallel()
	g := NewGuard(slog.Default())

	g.mu.Lock()
	g.limits["override@test.com"] = &UserLimits{
		MaxSingleOrderINR: domain.NewINR(100000),
		MaxDailyValueINR:  domain.NewINR(500000),
	}
	g.mu.Unlock()

	l := g.GetEffectiveLimits("override@test.com")
	assert.Equal(t, float64(100000), l.MaxSingleOrderINR.Float64())
	assert.Equal(t, float64(500000), l.MaxDailyValueINR.Float64())
}
