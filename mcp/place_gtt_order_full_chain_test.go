// place_gtt_order_full_chain_test.go — sibling integration test to
// TestPlaceOrder_FullChain_AuditAndRiskguard (commit 76e42be).
//
// Exercises the full chain for `place_gtt_order`:
//
//	tool call -> audit middleware -> CommandBus -> PlaceGTTUseCase ->
//	             broker.PlaceGTT
//
// EMPIRICAL CHAIN-SHAPE FINDING (preserved per dispatch surface-back):
//
//	place_gtt_order DOES NOT run through riskguard. Per PlaceGTTUseCase
//	source (algo2go/kite-mcp-usecases/gtt_usecases.go), the struct has
//	NO riskguard field — only brokerResolver + eventStore + events +
//	logger. GTT orders are deferred-execution triggers; the risk-budget
//	checks apply only when the trigger fires and the broker places a
//	concrete order on the user's behalf, which is out-of-band from this
//	tool call.
//
//	Like cancel_order, the test name follows the dispatch-spec naming
//	convention for consistency with the sibling tests, but the actual
//	assertion verifies only audit + broker — riskguard is bypassed
//	by design.
//
// No pre-seed needed: place_gtt_order creates a new GTT trigger from
// scratch. Use trigger_type=single for the simplest valid path
// (PlaceGTTOrderTool requires trigger_value > 0 for single-leg).
//
// Broker-state assertion: mock.Client.PlaceGTT appends to its internal
// gtts slice (algo2go/kite-mcp-broker/mock/client.go:637). Assert by
// reading GetGTTs() back and checking exactly 1 GTT exists with the
// correct symbol + trigger + transaction type.

package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algo2go/kite-mcp-audit"
	"github.com/algo2go/kite-mcp-oauth"
)

// TestPlaceGTTOrder_FullChain_AuditAndRiskguard exercises the place_gtt_order
// chain end-to-end. See file header for the riskguard-bypass-by-design note.
func TestPlaceGTTOrder_FullChain_AuditAndRiskguard(t *testing.T) {
	h := newFullChainHarness(t)

	// Pre-call broker state: no GTTs.
	gttsBefore, err := h.mockClient.GetGTTs()
	require.NoError(t, err)
	require.Empty(t, gttsBefore, "broker must have zero GTTs before the test call")

	// Build the audit-wrapped place_gtt_order handler.
	mw := audit.Middleware(h.auditStore)
	require.NotNil(t, mw)
	var rawHandler server.ToolHandlerFunc
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "place_gtt_order" {
			rawHandler = tool.Handler(h.mgr)
			break
		}
	}
	require.NotNil(t, rawHandler, "place_gtt_order tool must be registered")
	wrappedHandler := mw(rawHandler)

	// MCP call context.
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("place-gtt-order-chain-test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	// Build the place_gtt_order request — single-leg trigger.
	// Per PlaceGTTOrderTool required list (mcp/trade/gtt_tools.go:99):
	//   exchange, tradingsymbol, last_price, transaction_type, product, trigger_type
	// Plus per single-leg validation: trigger_value > 0.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_gtt_order"
	req.Params.Arguments = map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       1620.00,
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    1600.00, // trigger when price drops to 1600
		"quantity":         1.0,
		"limit_price":      1610.00,
	}

	// Execute. The chain MUST flow through audit middleware -> CommandBus
	// -> PlaceGTTUseCase -> broker.PlaceGTT. NO riskguard step.
	result, err := wrappedHandler(ctx, req)
	require.NoError(t, err, "handler must not return a top-level error on the allowed path")
	require.NotNil(t, result)
	assert.False(t, result.IsError,
		"place_gtt_order must succeed on the allowed path; got error result. Inspect: %+v", result)

	// (a) AUDIT ASSERTION
	assertAuditRowExists(t, h.auditStore, "place_gtt_order")

	// (b) CHAIN-COMPLETED ASSERTION (no riskguard step in this chain).
	// PlaceGTTUseCase reached broker.PlaceGTT, which appended a GTTOrder
	// to the mock's gtts slice.
	gttsAfter, err := h.mockClient.GetGTTs()
	require.NoError(t, err)
	require.Len(t, gttsAfter, 1,
		"mock broker must have recorded exactly 1 GTT; got %d. "+
			"If 0: the chain did not reach broker.PlaceGTT. "+
			"If >1: spurious duplicate dispatch.",
		len(gttsAfter))
	placedGTT := gttsAfter[0]
	assert.Equal(t, "single", placedGTT.Type)
	assert.Equal(t, "active", placedGTT.Status)
	assert.Equal(t, "NSE", placedGTT.Condition.Exchange)
	assert.Equal(t, "INFY", placedGTT.Condition.Tradingsymbol)
	require.Len(t, placedGTT.Condition.TriggerValues, 1,
		"single-leg GTT must have exactly 1 trigger value")
	assert.Equal(t, 1600.00, placedGTT.Condition.TriggerValues[0],
		"trigger value must match the request")
	require.Len(t, placedGTT.Orders, 1,
		"single-leg GTT must have exactly 1 order leg")
	assert.Equal(t, "BUY", placedGTT.Orders[0].TransactionType)
	assert.Equal(t, 1, placedGTT.Orders[0].Quantity)
	assert.Equal(t, "CNC", placedGTT.Orders[0].Product)
}
