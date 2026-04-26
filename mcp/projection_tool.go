package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetOrderProjectionTool exposes the read-side OrderAggregate projection
// through an MCP tool. State is accumulated in-process by the eventsourcing
// Projector subscribing to domain.EventDispatcher, so this tool returns the
// live view built from events dispatched by the write-side use cases since
// the server started. Unlike get_order_history (which calls the broker API),
// this is a locally-projected read model fed entirely by the domain event
// bus.
type GetOrderProjectionTool struct{}

func (*GetOrderProjectionTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_projection",
		mcp.WithDescription("Get the locally-projected state of an order, built from in-process domain events. Useful for debugging event flow and auditing the write-side event bus. Returns Found=false if no events have been dispatched for this order ID since server start."),
		mcp.WithTitleAnnotation("Get Order Projection"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("order_id",
			mcp.Description("ID of the order to look up in the projection store"),
			mcp.Required(),
		),
	)
}

func (*GetOrderProjectionTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_projection")
		p := NewArgParser(request.GetArguments())

		if err := p.Required("order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		orderID := p.String("order_id", "")

		return handler.WithSession(ctx, "get_order_projection", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetOrderProjectionQuery{
				Email:   session.Email,
				OrderID: orderID,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get order projection: %s", err.Error())), nil
			}
			res := raw.(cqrs.OrderProjectionResult)
			return handler.MarshalResponse(res, "get_order_projection")
		})
	}
}
