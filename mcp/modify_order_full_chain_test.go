// modify_order_full_chain_test.go — sibling integration test to
// TestPlaceOrder_FullChain_AuditAndRiskguard (commit 76e42be).
//
// Exercises the full chain for `modify_order`:
//
//	tool call -> audit middleware -> CommandBus -> ModifyOrderUseCase ->
//	             riskguard.CheckOrderCtx (Allowed) -> broker.ModifyOrder
//
// Per ModifyOrderUseCase source (algo2go/kite-mcp-usecases/modify_order.go),
// modify DOES run riskguard.CheckOrderCtx with the NEW order shape — unlike
// cancel_order which bypasses riskguard entirely. So this test's chain shape
// matches place_order: audit + riskguard + broker.
//
// Pre-seed: place a LIMIT order first so the mock has an OPEN order to
// modify. (MARKET orders are immediately COMPLETE in brokermock and cannot
// be modified per mock.Client.ModifyOrder:378 status check.)
//
// Broker-state assertion: modify mutates the order in-place (mock.Client.
// ModifyOrder:382-389 updates Quantity/Price/TriggerPrice/OrderType in the
// existing slice element). Assert by reading the order back and checking
// the new Price + Quantity reflect the modify request.

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

// TestModifyOrder_FullChain_AuditAndRiskguard exercises the modify_order
// chain end-to-end. See file header for design notes.
func TestModifyOrder_FullChain_AuditAndRiskguard(t *testing.T) {
	h := newFullChainHarness(t)

	// Pre-seed: place a LIMIT order directly through the mock so it
	// stays in OPEN status (MARKET orders auto-COMPLETE in brokermock).
	// This bypasses the tool layer for the seed step — we're not
	// testing place_order here.
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
	require.NotEmpty(t, placeResp.OrderID, "seed PlaceOrder must return a non-empty OrderID")
	seedOrderID := placeResp.OrderID

	// Verify the seeded order is OPEN and ready to be modified.
	ordersBefore, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersBefore, 1, "seed must produce exactly 1 order")
	require.Equal(t, "OPEN", ordersBefore[0].Status,
		"seed LIMIT order must be in OPEN status before modify")
	require.Equal(t, 1500.00, ordersBefore[0].Price,
		"seed order price must be 1500.00 (pre-modify)")
	require.Equal(t, 1, ordersBefore[0].Quantity,
		"seed order qty must be 1 (pre-modify)")

	// Build the audit-wrapped modify_order handler.
	mw := audit.Middleware(h.auditStore)
	require.NotNil(t, mw)
	var rawHandler server.ToolHandlerFunc
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "modify_order" {
			rawHandler = tool.Handler(h.mgr)
			break
		}
	}
	require.NotNil(t, rawHandler, "modify_order tool must be registered")
	wrappedHandler := mw(rawHandler)

	// MCP call context.
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("modify-order-chain-test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	// Build the modify_order request.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "modify_order"
	req.Params.Arguments = map[string]any{
		"variety":    "regular",
		"order_id":   seedOrderID,
		"quantity":   5,
		"price":      1550.00,
		"order_type": "LIMIT",
	}

	// Execute through the audit-wrapped handler. The chain MUST flow
	// through audit middleware, CommandBus, ModifyOrderUseCase,
	// riskguard.CheckOrderCtx (Allowed), then broker.ModifyOrder.
	result, err := wrappedHandler(ctx, req)
	require.NoError(t, err, "handler must not return a top-level error on the allowed path")
	require.NotNil(t, result)
	assert.False(t, result.IsError,
		"modify_order must succeed on the riskguard-allowed path; got error result. Inspect: %+v", result)

	// (a) AUDIT ASSERTION
	assertAuditRowExists(t, h.auditStore, "modify_order")

	// (b) RISKGUARD-CONSULTED + CHAIN-COMPLETED ASSERTION
	// ModifyOrderUseCase runs riskguard.CheckOrderCtx BEFORE broker.ModifyOrder.
	// If the broker order was mutated (new price/qty), the chain reached
	// the broker AND riskguard returned Allowed.
	ordersAfter, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersAfter, 1,
		"broker must still have exactly 1 order after modify (in-place mutation)")
	modifiedOrder := ordersAfter[0]
	assert.Equal(t, seedOrderID, modifiedOrder.OrderID,
		"order ID must be unchanged by modify")
	assert.Equal(t, 1550.00, modifiedOrder.Price,
		"price must reflect the modify request (1500.00 -> 1550.00); "+
			"if still 1500.00: chain did not reach broker.ModifyOrder")
	assert.Equal(t, 5, modifiedOrder.Quantity,
		"quantity must reflect the modify request (1 -> 5); "+
			"if still 1: chain did not reach broker.ModifyOrder")
	assert.Equal(t, "OPEN", modifiedOrder.Status,
		"order must remain OPEN after modify")
}
