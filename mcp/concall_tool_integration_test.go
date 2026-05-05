package mcp

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests for analyze_concall — moved here
// from mcp/analytics/concall_tool_test.go because they exercise
// callToolWithManager + newFullDevModeManager / newDevModeManager
// helpers that live in mcp/helpers_test.go. The tool itself is now
// registered from mcp/analytics via init(); these black-box tests
// invoke it by name.

// TestAnalyzeConcall_ValidSymbol verifies the tool returns structured metadata
// and a BSE announcements URL for a known NSE-listed symbol.
func TestAnalyzeConcall_ValidSymbol(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t) // seeds INFY instrument with NSE:INFY ID
	result := callToolWithManager(t, mgr, "analyze_concall", "trader@example.com", map[string]any{
		"symbol":  "INFY",
		"quarter": "Q4FY25",
	})
	assert.False(t, result.IsError, "valid symbol should not error, got: %s", resultText(t, result))
	text := resultText(t, result)
	assert.Contains(t, text, "INFY", "response should echo symbol")
	assert.Contains(t, text, "INFOSYS", "response should include company name")
	assert.Contains(t, text, "Q4FY25", "response should echo quarter")
	assert.Contains(t, text, "bseindia.com", "response should include BSE announcements URL")
	// Sanity: response must give the LLM a next-step instruction.
	assert.True(t,
		strings.Contains(strings.ToLower(text), "webfetch") ||
			strings.Contains(strings.ToLower(text), "tavily") ||
			strings.Contains(strings.ToLower(text), "fetch"),
		"response should guide LLM on fetching the transcript")
}

// TestAnalyzeConcall_InvalidSymbol verifies the tool surfaces a validation
// error when no symbol is provided (rather than silently returning garbage).
func TestAnalyzeConcall_InvalidSymbol(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "analyze_concall", "trader@example.com", map[string]any{
		"symbol": "", // empty → ValidateRequired rejects
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "symbol")
}

// TestAnalyzeConcall_UnknownSymbol verifies unknown tickers fall back to a
// generic BSE search hint (no hard error — the LLM can still try the URL).
func TestAnalyzeConcall_UnknownSymbol(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "analyze_concall", "trader@example.com", map[string]any{
		"symbol":  "NOSUCHSYMBOL",
		"quarter": "Q1FY26",
	})
	// We return a best-effort response even for unknown symbols — the BSE URL
	// still works as a search hint, and the document status flags "unknown".
	assert.False(t, result.IsError, "unknown symbol should not hard-error: %s", resultText(t, result))
	text := resultText(t, result)
	assert.Contains(t, text, "NOSUCHSYMBOL")
	assert.Contains(t, strings.ToLower(text), "unknown")
}

// TestAnalyzeConcall_DefaultQuarter verifies omitting quarter picks the most
// recent Indian fiscal quarter (inferred from current date).
func TestAnalyzeConcall_DefaultQuarter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "analyze_concall", "trader@example.com", map[string]any{
		"symbol": "INFY",
		// quarter intentionally omitted
	})
	assert.False(t, result.IsError, "default quarter should resolve: %s", resultText(t, result))
	text := resultText(t, result)
	// The default quarter must follow the Indian QxFYyy convention.
	assert.Regexp(t, `Q[1-4]FY\d{2}`, text, "default quarter must follow QxFYyy convention")
}
