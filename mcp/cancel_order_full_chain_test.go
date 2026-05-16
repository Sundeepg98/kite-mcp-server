// cancel_order_full_chain_test.go — sibling integration test to
// TestPlaceOrder_FullChain_AuditAndRiskguard (commit 76e42be).
//
// Exercises the full chain for `cancel_order`:
//
//	tool call -> audit middleware -> CommandBus -> CancelOrderUseCase ->
//	             broker.CancelOrder
//
// EMPIRICAL CHAIN-SHAPE FINDING (preserved per dispatch surface-back):
//
//	cancel_order DOES NOT run through riskguard. Per CancelOrderUseCase
//	source (algo2go/kite-mcp-usecases/cancel_order.go:18 comment):
//
//	    // Riskguard is not applied to cancels (cancelling reduces risk,
//	    // not increases it).
//
//	The use-case struct has no `riskguard` field. So the test name
//	(`_AuditAndRiskguard`) follows the dispatch-spec naming convention
//	for consistency with the sibling tests, but the actual assertion
//	verifies only audit + broker — riskguard is intentionally skipped
//	by design.
//
// Pre-seed: place a LIMIT order directly through the mock so it stays
// in OPEN status (cancel requires OPEN per mock.Client.CancelOrder:410).
//
// Broker-state assertion: cancel mutates the order's Status field to
// "CANCELLED" in-place (mock.Client.CancelOrder:413). Assert by reading
// the order back and checking Status == "CANCELLED".

package mcp

import (
	"context"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/algo2go/kite-mcp-audit"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-oauth"
)

// TestCancelOrder_FullChain_AuditAndRiskguard exercises the cancel_order
// chain end-to-end. See file header for the riskguard-bypass-by-design note.
func TestCancelOrder_FullChain_AuditAndRiskguard(t *testing.T) {
	h := newFullChainHarness(t)

	// Pre-seed: place a LIMIT order directly through the mock (stays OPEN).
	placeResp, err := h.mockClient.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        1,
		Price:           1500.00,
		Product:         "CNC",
		OrderType:       "LIMIT",
		Validity:        "DAY",
		Variety:         "regular",
	})
	require.NoError(t, err)
	require.NotEmpty(t, placeResp.OrderID)
	seedOrderID := placeResp.OrderID

	ordersBefore, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersBefore, 1)
	require.Equal(t, "OPEN", ordersBefore[0].Status,
		"seed LIMIT order must be OPEN before cancel")

	// Build the audit-wrapped cancel_order handler.
	mw := audit.Middleware(h.auditStore)
	require.NotNil(t, mw)
	var rawHandler server.ToolHandlerFunc
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "cancel_order" {
			rawHandler = tool.Handler(h.mgr)
			break
		}
	}
	require.NotNil(t, rawHandler, "cancel_order tool must be registered")
	wrappedHandler := mw(rawHandler)

	// MCP call context.
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("cancel-order-chain-test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	// Build the cancel_order request.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "cancel_order"
	req.Params.Arguments = map[string]any{
		"variety":  "regular",
		"order_id": seedOrderID,
	}

	// Execute. The chain MUST flow through audit middleware -> CommandBus
	// -> CancelOrderUseCase -> broker.CancelOrder. NO riskguard step.
	result, err := wrappedHandler(ctx, req)
	require.NoError(t, err, "handler must not return a top-level error on the allowed path")
	require.NotNil(t, result)
	assert.False(t, result.IsError,
		"cancel_order must succeed on the allowed path; got error result. Inspect: %+v", result)

	// (a) AUDIT ASSERTION
	assertAuditRowExists(t, h.auditStore, "cancel_order")

	// (b) CHAIN-COMPLETED ASSERTION (no riskguard step in this chain).
	// Cancel mutates the existing order's Status to "CANCELLED" in-place.
	ordersAfter, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersAfter, 1,
		"broker must still have 1 order after cancel (in-place status mutation)")
	cancelledOrder := ordersAfter[0]
	assert.Equal(t, seedOrderID, cancelledOrder.OrderID,
		"order ID must be unchanged by cancel")
	assert.Equal(t, "CANCELLED", cancelledOrder.Status,
		"order status must flip OPEN -> CANCELLED; "+
			"if still OPEN: chain did not reach broker.CancelOrder")
}
