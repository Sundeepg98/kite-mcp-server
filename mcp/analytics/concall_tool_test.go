package analytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests (TestAnalyzeConcall_ValidSymbol,
// _InvalidSymbol, _UnknownSymbol, _DefaultQuarter) that exercise
// callToolWithManager + newFullDevModeManager / newDevModeManager
// moved to mcp/concall_tool_test.go because those helpers live in
// the mcp package and require the kc.Manager wiring there. The pure
// tests below (tool definition + latest-quarter logic) stay here
// because they reference analytics-internal symbols
// (AnalyzeConcallTool, latestIndianFiscalQuarter).

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
