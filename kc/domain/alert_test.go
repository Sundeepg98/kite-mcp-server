package domain

// alert_test.go — unit tests for the Alert domain entity.
//
// The 8 lifecycle methods (ShouldTrigger, MarkTriggered, IsPercentageAlert,
// IsActive, MatchesInstrument, NeedsNotification, InstrumentKey,
// PercentageChange) are pure-function behavior on the canonical domain
// type. Per .claude/CLAUDE.md, pure functions require 100% coverage —
// the evaluator tests in kc/alerts exercise them at runtime but
// per-package -cover only credits in-package tests, so these tests live
// here.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAlert_IsComposite(t *testing.T) {
	t.Parallel()

	// Default / zero-value Alert is not composite.
	a := &Alert{}
	assert.False(t, a.IsComposite())

	// Explicit single alert type is not composite.
	a.AlertType = AlertTypeSingle
	assert.False(t, a.IsComposite())

	// Composite alert type is composite.
	a.AlertType = AlertTypeComposite
	assert.True(t, a.IsComposite())
}

func TestValidCompositeLogics(t *testing.T) {
	t.Parallel()

	assert.True(t, ValidCompositeLogics[CompositeLogicAnd], "AND must be valid")
	assert.True(t, ValidCompositeLogics[CompositeLogicAny], "ANY must be valid")
	assert.False(t, ValidCompositeLogics[CompositeLogic("XOR")], "XOR must be invalid")
	assert.False(t, ValidCompositeLogics[CompositeLogic("")], "empty logic must be invalid")
}

// TestAlert_ShouldTrigger covers the four direction branches and the
// reference-price guard (ReferencePrice <= 0 forces drop_pct/rise_pct
// to short-circuit to false rather than divide by zero).
func TestAlert_ShouldTrigger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		direction      Direction
		target         float64
		refPrice       float64
		current        float64
		want           bool
	}{
		{"above: at target fires", DirectionAbove, 100, 0, 100, true},
		{"above: above target fires", DirectionAbove, 100, 0, 105, true},
		{"above: below target silent", DirectionAbove, 100, 0, 99, false},
		{"below: at target fires", DirectionBelow, 100, 0, 100, true},
		{"below: below target fires", DirectionBelow, 100, 0, 95, true},
		{"below: above target silent", DirectionBelow, 100, 0, 101, false},
		{"drop_pct: 5% drop fires at threshold 5", DirectionDropPct, 5, 1000, 950, true},
		{"drop_pct: 4% drop silent at threshold 5", DirectionDropPct, 5, 1000, 960, false},
		{"drop_pct: zero ref price short-circuits false", DirectionDropPct, 5, 0, 950, false},
		{"drop_pct: negative ref price short-circuits false", DirectionDropPct, 5, -100, 950, false},
		{"rise_pct: 10% rise fires at threshold 10", DirectionRisePct, 10, 1000, 1100, true},
		{"rise_pct: 9% rise silent at threshold 10", DirectionRisePct, 10, 1000, 1090, false},
		{"rise_pct: zero ref price short-circuits false", DirectionRisePct, 10, 0, 1100, false},
		{"unknown direction returns false (default branch)", Direction("XYZ"), 100, 0, 200, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Alert{
				Direction:      tc.direction,
				TargetPrice:    tc.target,
				ReferencePrice: tc.refPrice,
			}
			if got := a.ShouldTrigger(tc.current); got != tc.want {
				t.Errorf("ShouldTrigger(%v) = %v, want %v", tc.current, got, tc.want)
			}
		})
	}
}

// TestAlert_MarkTriggered covers the first-fire vs already-triggered
// branches. First call must return true and stamp the trigger fields;
// subsequent calls must return false and leave state untouched (so the
// alert evaluator can safely double-call).
func TestAlert_MarkTriggered(t *testing.T) {
	t.Parallel()

	a := &Alert{}
	if !a.MarkTriggered(105.0) {
		t.Fatal("first MarkTriggered should return true")
	}
	if !a.Triggered {
		t.Error("Triggered flag should be set after first MarkTriggered")
	}
	if a.TriggeredPrice != 105.0 {
		t.Errorf("TriggeredPrice = %v, want 105.0", a.TriggeredPrice)
	}
	if a.TriggeredAt.IsZero() {
		t.Error("TriggeredAt should be populated")
	}

	// Second call: must return false, must not overwrite price.
	originalAt := a.TriggeredAt
	if a.MarkTriggered(200.0) {
		t.Error("second MarkTriggered should return false (idempotent)")
	}
	if a.TriggeredPrice != 105.0 {
		t.Errorf("TriggeredPrice changed to %v after second call, must stay 105.0", a.TriggeredPrice)
	}
	if !a.TriggeredAt.Equal(originalAt) {
		t.Errorf("TriggeredAt changed on second call: %v vs %v", a.TriggeredAt, originalAt)
	}
}

// TestAlert_IsPercentageAlert covers all four direction branches.
func TestAlert_IsPercentageAlert(t *testing.T) {
	t.Parallel()
	tests := []struct {
		direction Direction
		want      bool
	}{
		{DirectionAbove, false},
		{DirectionBelow, false},
		{DirectionDropPct, true},
		{DirectionRisePct, true},
	}
	for _, tc := range tests {
		t.Run(string(tc.direction), func(t *testing.T) {
			a := &Alert{Direction: tc.direction}
			if got := a.IsPercentageAlert(); got != tc.want {
				t.Errorf("IsPercentageAlert() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAlert_IsActive covers both Triggered states.
func TestAlert_IsActive(t *testing.T) {
	t.Parallel()
	a := &Alert{}
	if !a.IsActive() {
		t.Error("zero-value Alert should be active")
	}
	a.Triggered = true
	if a.IsActive() {
		t.Error("triggered Alert should not be active")
	}
}

// TestAlert_MatchesInstrument covers the equal/unequal token paths.
func TestAlert_MatchesInstrument(t *testing.T) {
	t.Parallel()
	a := &Alert{InstrumentToken: 408065}
	if !a.MatchesInstrument(408065) {
		t.Error("matching token should return true")
	}
	if a.MatchesInstrument(99999) {
		t.Error("non-matching token should return false")
	}
}

// TestAlert_NeedsNotification covers the (Triggered + zero NotifiedAt)
// AND-condition. Both halves of the AND must be tested independently.
func TestAlert_NeedsNotification(t *testing.T) {
	t.Parallel()

	// Not triggered + zero NotificationSentAt: no notification needed.
	a := &Alert{}
	if a.NeedsNotification() {
		t.Error("untriggered alert should not need notification")
	}

	// Triggered + zero NotificationSentAt: needs notification.
	a.Triggered = true
	if !a.NeedsNotification() {
		t.Error("triggered alert with zero NotifiedAt should need notification")
	}

	// Triggered + non-zero NotificationSentAt: notification already sent.
	a.NotificationSentAt = time.Now()
	if a.NeedsNotification() {
		t.Error("alert with NotifiedAt set should not need notification again")
	}
}

// TestAlert_InstrumentKey pins the "exchange:tradingsymbol" format.
func TestAlert_InstrumentKey(t *testing.T) {
	t.Parallel()
	a := &Alert{Exchange: "NSE", Tradingsymbol: "RELIANCE"}
	if got := a.InstrumentKey(); got != "NSE:RELIANCE" {
		t.Errorf("InstrumentKey() = %q, want NSE:RELIANCE", got)
	}

	// Empty fields produce a single colon — defence-in-depth check.
	zero := &Alert{}
	if got := zero.InstrumentKey(); got != ":" {
		t.Errorf("zero-value InstrumentKey() = %q, want %q", got, ":")
	}
}

// TestAlert_PercentageChange covers the signed-arithmetic branches and
// the zero/negative reference-price guard.
func TestAlert_PercentageChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		refPrice float64
		current  float64
		want     float64
	}{
		{"10% rise from 1000", 1000, 1100, 10},
		{"5% drop from 1000 (negative result)", 1000, 950, -5},
		{"zero ref price short-circuits to 0", 0, 1100, 0},
		{"negative ref price short-circuits to 0", -100, 1100, 0},
		{"flat (no change)", 1000, 1000, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &Alert{ReferencePrice: tc.refPrice}
			got := a.PercentageChange(tc.current)
			if got != tc.want {
				t.Errorf("PercentageChange(%v) = %v, want %v", tc.current, got, tc.want)
			}
		})
	}
}
