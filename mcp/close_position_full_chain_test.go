// close_position_full_chain_test.go — sibling integration test to
// TestPlaceOrder_FullChain_AuditAndRiskguard (commit 76e42be).
//
// Exercises the full chain for `close_position`:
//
//	tool call -> audit middleware -> CommandBus -> ClosePositionUseCase ->
//	             riskguard.CheckOrderCtx (Allowed) -> broker.PlaceOrder
//	             (opposite-direction MARKET order)
//
// Per ClosePositionUseCase source (algo2go/kite-mcp-usecases/close_position.go:118-149),
// close_position runs riskguard.CheckOrderCtx on the SYNTHETIC opposite
// order (Confirmed=true since the user already confirmed via elicitation
// at the tool boundary). So this test's chain shape matches place_order:
// audit + riskguard + broker.
//
// Pre-seed: pre-populate the mock with an OPEN long position so the use
// case has something to find via client.GetPositions(). The use case
// derives the opposite direction (long position -> SELL MARKET order).
//
// Broker-state assertion: close_position results in a NEW MARKET order
// being placed (the opposite-direction close-out). Per brokermock,
// MARKET orders are immediately COMPLETE. Assert by reading orders back
// and finding a SELL MARKET INFY order with the matching quantity.

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
	"github.com/algo2go/kite-mcp-money"
	"github.com/algo2go/kite-mcp-oauth"
)

// TestClosePosition_FullChain_AuditAndRiskguard exercises the close_position
// chain end-to-end. See file header for design notes.
func TestClosePosition_FullChain_AuditAndRiskguard(t *testing.T) {
	h := newFullChainHarness(t)

	// Pre-seed: a long INFY position with quantity 10 @ avg 1500.
	// ClosePositionUseCase will detect this via client.GetPositions(),
	// determine the opposite direction (SELL), and place a SELL MARKET
	// order for 10 shares.
	h.mockClient.SetPositions(broker.Positions{
		Net: []broker.Position{
			{
				Exchange:      "NSE",
				Tradingsymbol: "INFY",
				Product:       "CNC",
				Quantity:      10,      // positive = long
				AveragePrice:  1500.00,
				LastPrice:     1620.00, // matches the seeded price for realism
				PnL:           money.NewINR(1200.00), // (1620 - 1500) * 10
			},
		},
	})

	// Pre-call: zero orders (the close will create exactly 1).
	ordersBefore, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Empty(t, ordersBefore, "broker must have zero orders before close_position")

	// Build the audit-wrapped close_position handler.
	mw := audit.Middleware(h.auditStore)
	require.NotNil(t, mw)
	var rawHandler server.ToolHandlerFunc
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "close_position" {
			rawHandler = tool.Handler(h.mgr)
			break
		}
	}
	require.NotNil(t, rawHandler, "close_position tool must be registered")
	wrappedHandler := mw(rawHandler)

	// MCP call context.
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("close-position-chain-test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	// Build the close_position request — per ClosePositionTool required
	// list (mcp/trade/exit_tools.go:44): just `instrument` in
	// "exchange:symbol" format. `product` filter is optional; we omit it
	// so the use case matches the first position regardless of product.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "close_position"
	req.Params.Arguments = map[string]any{
		"instrument": "NSE:INFY",
	}

	// Execute. The chain MUST flow through audit middleware -> CommandBus
	// -> ClosePositionUseCase -> client.GetPositions() (finds the long) ->
	// riskguard.CheckOrderCtx (Allowed on synthetic SELL MARKET 10) ->
	// client.PlaceOrder (the close-out order).
	result, err := wrappedHandler(ctx, req)
	require.NoError(t, err, "handler must not return a top-level error on the allowed path")
	require.NotNil(t, result)
	assert.False(t, result.IsError,
		"close_position must succeed on the riskguard-allowed path; got error result. Inspect: %+v", result)

	// (a) AUDIT ASSERTION
	assertAuditRowExists(t, h.auditStore, "close_position")

	// (b) RISKGUARD-CONSULTED + CHAIN-COMPLETED ASSERTION
	// ClosePositionUseCase runs riskguard.CheckOrderCtx BEFORE the
	// broker.PlaceOrder for the opposite-direction close-out. A broker-
	// recorded order is direct proof that riskguard returned Allowed AND
	// the chain reached broker.PlaceOrder.
	ordersAfter, err := h.mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersAfter, 1,
		"broker must have recorded exactly 1 close-out order; got %d. "+
			"If 0: chain did not reach broker.PlaceOrder (riskguard rejected, "+
			"position not found, or use-case errored). "+
			"If >1: spurious duplicate dispatch.",
		len(ordersAfter))
	closeOrder := ordersAfter[0]
	assert.Equal(t, "INFY", closeOrder.Tradingsymbol)
	assert.Equal(t, "NSE", closeOrder.Exchange)
	// Opposite-direction: long (qty=10) -> SELL.
	assert.Equal(t, "SELL", closeOrder.TransactionType,
		"close-out for a long position must be a SELL order; "+
			"if BUY: opposite-direction logic is broken")
	assert.Equal(t, "MARKET", closeOrder.OrderType,
		"close-out must be a MARKET order (immediate fill)")
	assert.Equal(t, 10, closeOrder.Quantity,
		"close-out quantity must equal the absolute position quantity")
	assert.Equal(t, "CNC", closeOrder.Product,
		"close-out product must match the position's product")
}
