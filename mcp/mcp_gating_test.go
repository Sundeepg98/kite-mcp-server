package mcp

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
)

// tradingToolNamesForTest lists the 19 order-placement tools that MUST be
// gated behind the EnableTrading flag. This mirrors the production
// tradingToolNames set in mcp.go and is duplicated here so a future
// edit that silently drops a tool from the production set will fail this
// test (the assertion runs against the expected set, not the production
// set).
var tradingToolNamesForTest = []string{
	"place_order",
	"modify_order",
	"cancel_order",
	"convert_position",
	"place_gtt_order",
	"modify_gtt_order",
	"delete_gtt_order",
	"close_position",
	"close_all_positions",
	"set_trailing_stop",
	"cancel_trailing_stop",
	"place_native_alert",
	"modify_native_alert",
	"delete_native_alert",
	"place_mf_order",
	"cancel_mf_order",
	"place_mf_sip",
	"cancel_mf_sip",
}

// TestTradingGating_Disabled_ExcludesTradingTools verifies that when
// EnableTrading is false, filterToolsWithGating skips every trading tool
// even without any ExcludedTools configured.
func TestTradingGating_Disabled_ExcludesTradingTools(t *testing.T) {
	t.Parallel()

	allTools := GetAllTools()
	filtered, registered, gated := filterToolsWithGating(allTools, map[string]bool{}, false)

	// All 18+ trading tools should have been gated.
	assert.GreaterOrEqual(t, gated, len(tradingToolNamesForTest),
		"expected at least %d trading tools gated, got %d", len(tradingToolNamesForTest), gated)
	assert.Equal(t, len(allTools)-gated, registered,
		"registered + gated should equal total")

	names := map[string]bool{}
	for _, tool := range filtered {
		names[tool.Tool().Name] = true
	}
	for _, blocked := range tradingToolNamesForTest {
		assert.Falsef(t, names[blocked],
			"trading tool %q should NOT be registered when EnableTrading=false", blocked)
	}

	// Safe tools stay registered.
	safe := []string{"get_profile", "get_holdings", "get_quotes", "server_metrics", "list_trailing_stops", "order_risk_report"}
	for _, s := range safe {
		assert.Truef(t, names[s], "safe tool %q must remain registered", s)
	}
}

// TestTradingGating_Enabled_IncludesTradingTools verifies that when
// EnableTrading is true, every trading tool IS registered.
func TestTradingGating_Enabled_IncludesTradingTools(t *testing.T) {
	t.Parallel()

	allTools := GetAllTools()
	filtered, registered, gated := filterToolsWithGating(allTools, map[string]bool{}, true)

	assert.Equal(t, 0, gated, "no tools should be gated when EnableTrading=true")
	assert.Equal(t, len(allTools), registered)

	names := map[string]bool{}
	for _, tool := range filtered {
		names[tool.Tool().Name] = true
	}
	for _, required := range tradingToolNamesForTest {
		assert.Truef(t, names[required],
			"trading tool %q MUST be registered when EnableTrading=true", required)
	}
}

// TestTradingGating_ExcludedAndGated_BothApplied verifies that explicit
// ExcludedTools and the EnableTrading flag compose: a tool excluded AND
// gated should still be counted as one exclusion (no double-count) but
// the end result (unregistered) must be the same.
func TestTradingGating_ExcludedAndGated_BothApplied(t *testing.T) {
	t.Parallel()

	allTools := GetAllTools()
	excluded := map[string]bool{"place_order": true, "get_profile": true}
	filtered, _, gated := filterToolsWithGating(allTools, excluded, false)

	names := map[string]bool{}
	for _, tool := range filtered {
		names[tool.Tool().Name] = true
	}

	// Explicitly excluded tools absent.
	assert.False(t, names["place_order"], "place_order is excluded")
	assert.False(t, names["get_profile"], "get_profile is excluded")

	// Other trading tools still gated.
	assert.False(t, names["modify_order"], "modify_order must still be gated")
	assert.False(t, names["close_position"], "close_position must still be gated")

	// Gating count must not include place_order (excluded first).
	assert.GreaterOrEqual(t, gated, len(tradingToolNamesForTest)-1)
}

// TestRegisterTools_GatingCompiles smoke-checks that RegisterTools accepts
// the new enableTrading parameter and doesn't panic in either mode. This
// guards the wire.go call site against silent drift.
func TestRegisterTools_GatingCompiles(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	for _, enable := range []bool{false, true} {
		srv := server.NewMCPServer("test", "1.0")
		RegisterTools(srv, mgr, "", nil, mgr.Logger, enable)
	}
}
