package mcp

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// path2_integration_test.go — end-to-end integration tests proving that
// the ENABLE_TRADING env flag actually gates order-placement tools out of
// the MCP server registration (not just the filter function in isolation).
//
// These tests initialize the full production registration flow via
// RegisterTools() against a real server.MCPServer and inspect the registry
// via ListTools(). This guards against a future refactor that leaves
// filterToolsWithGating() intact but forgets to thread its output into
// RegisterTools — a drift that unit-level gating tests would miss.
//
// Paired with:
//   - mcp_gating_test.go (unit-level filter logic — Agent 52)
//   - tools_pure_test.go::TestRegisterTools_Basic (smoke-level compile check)
//
// Why this matters: NSE/INVG/69255 Annexure I Para 2.8 ("Algo Provider")
// treats an automated order path as algo trading. Path 2 hosted deployment
// (Fly.io) must refuse to register any tool that places, modifies, or
// cancels an order on a real Kite account. ENABLE_TRADING=false is the
// 5-minute regulator panic button documented in docs/incident-response.md
// Scenario 1-C — these tests prove it actually works end-to-end.

// path2BlockedTradingTools lists the 18 order-placement tools that MUST be
// absent from the MCP registry when ENABLE_TRADING=false. Intentionally
// duplicated from tradingToolNames (mcp.go) and tradingToolNamesForTest
// (mcp_gating_test.go) so a silent drop from the production set fails
// here against this expected list, not against a self-referential read.
var path2BlockedTradingTools = []string{
	// Equity/F&O order lifecycle
	"place_order",
	"modify_order",
	"cancel_order",
	"convert_position",
	// GTT order lifecycle
	"place_gtt_order",
	"modify_gtt_order",
	"delete_gtt_order",
	// Exit helpers (auto-fire place_order / modify_order under the hood)
	"close_position",
	"close_all_positions",
	// Trailing stop-loss (fires modify_order on each trail step)
	"set_trailing_stop",
	"cancel_trailing_stop",
	// Native Kite server-side alerts (ATO can auto-place orders)
	"place_native_alert",
	"modify_native_alert",
	"delete_native_alert",
	// Mutual fund order/SIP lifecycle
	"place_mf_order",
	"cancel_mf_order",
	"place_mf_sip",
	"cancel_mf_sip",
}

// path2AlwaysRegisteredDataTools lists read-only tools that are NEVER gated
// by ENABLE_TRADING — they must remain registered in both modes so Path 2
// hosted users can still read their holdings, quotes, research data, etc.
var path2AlwaysRegisteredDataTools = []string{
	"get_holdings",
	"get_positions",
	"get_orders",
	"get_trades",
	"get_quotes",
	"get_ltp",
	"get_historical_data",
	"analyze_concall",
	"get_fii_dii_flow",
	"peer_compare",
	"server_version",
}

// registerToolsForPath2Test initializes a real MCPServer via the production
// RegisterTools() path with the given enableTrading flag, then returns the
// server for inspection. Using the full production call avoids any
// drift between what the test measures and what ships.
func registerToolsForPath2Test(t *testing.T, enableTrading bool) *server.MCPServer {
	t.Helper()
	mgr := newTestManager(t)
	srv := server.NewMCPServer("path2-integration-test", "1.0")
	RegisterTools(srv, mgr, "", nil, mgr.Logger, enableTrading)
	return srv
}

// assertRegistered asserts that the given tool name IS present in the
// server's tool registry.
func assertRegistered(t *testing.T, srv *server.MCPServer, toolName string) {
	t.Helper()
	tools := srv.ListTools()
	require.NotNil(t, tools, "server must have at least one tool registered")
	_, ok := tools[toolName]
	assert.Truef(t, ok, "tool %q MUST be registered but is absent from ListTools()", toolName)
}

// assertNotRegistered asserts that the given tool name is ABSENT from the
// server's tool registry.
func assertNotRegistered(t *testing.T, srv *server.MCPServer, toolName string) {
	t.Helper()
	tools := srv.ListTools()
	// tools may be nil if no tools were registered at all; that is still
	// "not registered" for this assertion's purposes.
	if tools == nil {
		return
	}
	_, ok := tools[toolName]
	assert.Falsef(t, ok, "tool %q MUST NOT be registered when gated but is present in ListTools()", toolName)
}

// TestPath2_TradingDisabled_HidesOrderTools is the primary Path 2 compliance
// guard: with ENABLE_TRADING=false (Fly.io hosted default), none of the
// order-placement tools may appear in the MCP server's registered tool set.
func TestPath2_TradingDisabled_HidesOrderTools(t *testing.T) {
	t.Parallel()

	srv := registerToolsForPath2Test(t, false)

	// Sanity: server has tools registered (not an empty registry due to
	// some unrelated failure).
	tools := srv.ListTools()
	require.NotNil(t, tools, "tools registry must not be nil")
	assert.Greater(t, len(tools), 0, "at least one tool must be registered")

	// Each of the 18 trading tools must be absent.
	for _, blocked := range path2BlockedTradingTools {
		assertNotRegistered(t, srv, blocked)
	}

	// Verify the count of blocked tools matches what we expect (guards
	// against a silent shrink of the list above).
	assert.Equal(t, 18, len(path2BlockedTradingTools),
		"expected 18 blocked trading tools — update the list above if the production set changed")
}

// TestPath2_TradingEnabled_ExposesOrderTools verifies the inverse: with
// ENABLE_TRADING=true (local dev / personal-use safe harbor), every
// previously-gated trading tool IS registered. This proves the gate is
// a real boolean switch, not a one-way removal.
func TestPath2_TradingEnabled_ExposesOrderTools(t *testing.T) {
	t.Parallel()

	srv := registerToolsForPath2Test(t, true)

	tools := srv.ListTools()
	require.NotNil(t, tools, "tools registry must not be nil")

	// Each of the 18 trading tools must be present.
	for _, required := range path2BlockedTradingTools {
		assertRegistered(t, srv, required)
	}

	assert.Equal(t, 18, len(path2BlockedTradingTools),
		"expected 18 trading tools — update the list above if the production set changed")
}

// TestPath2_DataToolsAlwaysRegistered verifies that read-only data/research
// tools stay registered in BOTH modes. These tools do not place orders so
// they are Path 2 compliant regardless of ENABLE_TRADING.
func TestPath2_DataToolsAlwaysRegistered(t *testing.T) {
	t.Parallel()

	// Mode 1: ENABLE_TRADING=false (hosted Path 2).
	srvDisabled := registerToolsForPath2Test(t, false)
	for _, dataTool := range path2AlwaysRegisteredDataTools {
		assertRegistered(t, srvDisabled, dataTool)
	}

	// Mode 2: ENABLE_TRADING=true (local personal-use).
	srvEnabled := registerToolsForPath2Test(t, true)
	for _, dataTool := range path2AlwaysRegisteredDataTools {
		assertRegistered(t, srvEnabled, dataTool)
	}

	assert.Equal(t, 11, len(path2AlwaysRegisteredDataTools),
		"expected 11 always-registered data tools — update the list above if the invariant changed")
}
