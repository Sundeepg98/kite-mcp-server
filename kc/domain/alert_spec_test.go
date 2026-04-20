package domain

// alert_spec_test.go — unit tests for the Alert construction invariants.
// Covers threshold validation, direction whitelist, and reference-price
// sanity for percentage-change alerts. These rules previously lived
// duplicated across create_alert.go, alert_aggregate.go, and
// telegram/trading_commands.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- ValidateAlertSpec: above/below directions ---

func TestValidateAlertSpec_Above_RejectsZeroTarget(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionAbove, 0, 0)
	assert.Error(t, err)
}

func TestValidateAlertSpec_Above_RejectsNegativeTarget(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionAbove, -10, 0)
	assert.Error(t, err)
}

func TestValidateAlertSpec_Above_AcceptsPositive(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionAbove, 2500.50, 0)
	assert.NoError(t, err)
}

func TestValidateAlertSpec_Below_AcceptsPositive(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionBelow, 100, 0)
	assert.NoError(t, err)
}

// --- ValidateAlertSpec: percentage directions ---

func TestValidateAlertSpec_DropPct_RequiresRefPrice(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionDropPct, 5, 0)
	assert.Error(t, err)
}

func TestValidateAlertSpec_DropPct_RejectsNegativeRefPrice(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionDropPct, 5, -100)
	assert.Error(t, err)
}

func TestValidateAlertSpec_DropPct_RejectsThresholdOver100(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionDropPct, 150, 2500)
	assert.Error(t, err, "can't drop by >100%")
}

func TestValidateAlertSpec_DropPct_AcceptsReasonable(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionDropPct, 10, 2500)
	assert.NoError(t, err)
}

func TestValidateAlertSpec_RisePct_RequiresRefPrice(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionRisePct, 5, 0)
	assert.Error(t, err)
}

func TestValidateAlertSpec_RisePct_AcceptsReasonable(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(DirectionRisePct, 15, 1200.75)
	assert.NoError(t, err)
}

// --- ValidateAlertSpec: direction whitelist ---

func TestValidateAlertSpec_RejectsUnknownDirection(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(Direction("sideways"), 10, 0)
	assert.Error(t, err)
}

func TestValidateAlertSpec_RejectsEmptyDirection(t *testing.T) {
	t.Parallel()

	err := ValidateAlertSpec(Direction(""), 10, 0)
	assert.Error(t, err)
}

// --- NewCompositeConditionStrict ---

func TestNewCompositeConditionStrict_RejectsEmptySymbol(t *testing.T) {
	t.Parallel()

	_, err := NewCompositeConditionStrict("NSE", "", DirectionAbove, 100, 0)
	assert.Error(t, err)
}

func TestNewCompositeConditionStrict_RejectsEmptyExchange(t *testing.T) {
	t.Parallel()

	_, err := NewCompositeConditionStrict("", "RELIANCE", DirectionAbove, 100, 0)
	assert.Error(t, err)
}

func TestNewCompositeConditionStrict_RejectsBadDirection(t *testing.T) {
	t.Parallel()

	_, err := NewCompositeConditionStrict("NSE", "RELIANCE", Direction("weird"), 100, 0)
	assert.Error(t, err)
}

func TestNewCompositeConditionStrict_RejectsZeroTarget(t *testing.T) {
	t.Parallel()

	_, err := NewCompositeConditionStrict("NSE", "RELIANCE", DirectionAbove, 0, 0)
	assert.Error(t, err)
}

func TestNewCompositeConditionStrict_PercentageRequiresRefPrice(t *testing.T) {
	t.Parallel()

	_, err := NewCompositeConditionStrict("NSE", "RELIANCE", DirectionDropPct, 5, 0)
	assert.Error(t, err)
}

func TestNewCompositeConditionStrict_AcceptsAbove(t *testing.T) {
	t.Parallel()

	c, err := NewCompositeConditionStrict("NSE", "RELIANCE", DirectionAbove, 2500, 0)
	assert.NoError(t, err)
	assert.Equal(t, "NSE", c.Exchange)
	assert.Equal(t, "RELIANCE", c.Tradingsymbol)
	assert.Equal(t, 2500.0, c.Value)
}

func TestNewCompositeConditionStrict_AcceptsDropPctWithRefPrice(t *testing.T) {
	t.Parallel()

	c, err := NewCompositeConditionStrict("NSE", "RELIANCE", DirectionDropPct, 5, 2500)
	assert.NoError(t, err)
	assert.Equal(t, 2500.0, c.ReferencePrice)
}
