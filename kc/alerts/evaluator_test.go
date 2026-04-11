package alerts

// evaluator_test.go -- tests for alert evaluation logic (Alert.ShouldTrigger, Evaluator).
// Extracted from coverage_test.go.
import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/gokiteconnect/v4/models"
)
func TestEvaluator_Above(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	s.Add("user@example.com", "INFY", "NSE", 408065, 1600.0, DirectionAbove)
	eval := NewEvaluator(s, defaultTestLogger())

	// Price below target: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1500})
	assert.Empty(t, notified)

	// Price at target: trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1600})
	assert.Len(t, notified, 1)
}

func TestEvaluator_Below(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	s.Add("user@example.com", "INFY", "NSE", 408065, 1400.0, DirectionBelow)
	eval := NewEvaluator(s, defaultTestLogger())

	// Price above target: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1500})
	assert.Empty(t, notified)

	// Price at target: trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1400})
	assert.Len(t, notified, 1)
}

func TestEvaluator_DropPct(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Alert: trigger when price drops 5% from reference 1000
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 1000.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// 3% drop: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 970})
	assert.Empty(t, notified)

	// 5% drop (price 950): trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 950})
	assert.Len(t, notified, 1)
}

func TestEvaluator_RisePct(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Alert: trigger when price rises 10% from reference 1000
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 10.0, DirectionRisePct, 1000.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// 5% rise: no trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1050})
	assert.Empty(t, notified)

	// 10% rise (price 1100): trigger
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1100})
	assert.Len(t, notified, 1)
}

func TestEvaluator_DropPct_ZeroReference(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	// Reference price 0 -> should never trigger
	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 0)
	eval := NewEvaluator(s, defaultTestLogger())

	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 0})
	assert.Empty(t, notified)
}

func TestEvaluator_NoAlerts(t *testing.T) {
	t.Parallel()
	s := NewStore(nil)
	eval := NewEvaluator(s, defaultTestLogger())

	// Should not panic
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 999999, LastPrice: 100})
}

func TestShouldTrigger_InvalidDirection_Coverage(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: Direction("unknown"), TargetPrice: 100}
	assert.False(t, a.ShouldTrigger(100))
}

// ===========================================================================
// TrailingStop — CancelByEmail
// ===========================================================================

func TestIsPercentageDirection_Coverage(t *testing.T) {
	t.Parallel()
	assert.True(t, IsPercentageDirection(DirectionDropPct))
	assert.True(t, IsPercentageDirection(DirectionRisePct))
	assert.False(t, IsPercentageDirection(DirectionAbove))
	assert.False(t, IsPercentageDirection(DirectionBelow))
}

// ===========================================================================
// Store — DB persistence tests
// ===========================================================================
