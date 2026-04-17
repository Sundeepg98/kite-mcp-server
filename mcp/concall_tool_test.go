package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestAnalyzeConcallTool_ToolDefinition verifies the tool registration metadata
// (name, description, read-only annotation) so the tool is surfaced correctly
// to MCP clients.
func TestAnalyzeConcallTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&AnalyzeConcallTool{}).Tool()
	assert.Equal(t, "analyze_concall", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.NotNil(t, tool.Annotations.ReadOnlyHint, "analyze_concall must be marked read-only")
	assert.True(t, *tool.Annotations.ReadOnlyHint, "analyze_concall must be marked read-only")
}

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

// TestLatestIndianFiscalQuarter verifies pure logic for inferring the most
// recent completed Indian fiscal quarter from a reference date. Indian fiscal
// year starts in April: Q1 = Apr–Jun, Q2 = Jul–Sep, Q3 = Oct–Dec, Q4 = Jan–Mar.
// Concall reports typically land 30–60 days AFTER quarter-end, so we return
// the most recently completed quarter (not the current one in progress).
func TestLatestIndianFiscalQuarter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		now  time.Time
		want string
	}{
		// April 17, 2026 → Q4FY26 just ended (Jan–Mar 2026), results out now.
		{"mid-April 2026", time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC), "Q4FY26"},
		// July 15 → Q1 just ended (Apr–Jun), results out late-July.
		{"mid-July 2025", time.Date(2025, 7, 15, 0, 0, 0, 0, time.UTC), "Q1FY26"},
		// October 5 → Q2 just ended (Jul–Sep).
		{"early-October 2025", time.Date(2025, 10, 5, 0, 0, 0, 0, time.UTC), "Q2FY26"},
		// January 20 → Q3 just ended (Oct–Dec).
		{"late-January 2026", time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC), "Q3FY26"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := latestIndianFiscalQuarter(tc.now)
			assert.Equal(t, tc.want, got)
		})
	}
}
