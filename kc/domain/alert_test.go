package domain

// alert_test.go — unit tests for the composite-alert domain additions.
// Keeps tests close to the types they exercise; existing Alert behavior
// (ShouldTrigger, MarkTriggered, etc.) is covered by the evaluator tests
// in kc/alerts which drive Alert through realistic tick-by-tick scenarios.

import (
	"testing"

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
