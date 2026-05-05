package analytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests for get_fii_dii_flow that exercise
// callToolWithManager moved to mcp/fii_dii_tool_integration_test.go.
// The pure tests below stay here because they reference analytics-internal
// symbols (GetFIIDIIFlowTool, latestTradingDay).

// TestGetFIIDIIFlowTool_ToolDefinition verifies the tool registration metadata
// (name, description, read-only annotation) so the tool is surfaced correctly
// to MCP clients.
func TestGetFIIDIIFlowTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&GetFIIDIIFlowTool{}).Tool()
	assert.Equal(t, "get_fii_dii_flow", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.NotNil(t, tool.Annotations.ReadOnlyHint, "get_fii_dii_flow must be marked read-only")
	assert.True(t, *tool.Annotations.ReadOnlyHint, "get_fii_dii_flow must be marked read-only")
}

// TestLatestTradingDay verifies the fallback default-date helper returns a
// non-empty YYYY-MM-DD string that skips weekends.
func TestLatestTradingDay(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		now  time.Time
		want string
	}{
		// Friday 2026-04-17 → itself (trading day).
		{"Friday returns itself", time.Date(2026, 4, 17, 10, 0, 0, 0, time.UTC), "2026-04-17"},
		// Saturday 2026-04-18 → previous Friday 2026-04-17.
		{"Saturday rolls back to Friday", time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC), "2026-04-17"},
		// Sunday 2026-04-19 → previous Friday 2026-04-17.
		{"Sunday rolls back to Friday", time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC), "2026-04-17"},
		// Monday 2026-04-20 → itself.
		{"Monday returns itself", time.Date(2026, 4, 20, 10, 0, 0, 0, time.UTC), "2026-04-20"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := latestTradingDay(tc.now)
			assert.Equal(t, tc.want, got)
		})
	}
}
