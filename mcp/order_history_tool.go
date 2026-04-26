package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetOrderHistoryReconstitutedTool exposes event-sourced order lifecycle
// reconstitution as an MCP tool. Unlike get_order_projection (which reads the
// in-process Projector, lost on restart) and get_order_history (which calls
// the broker API), this tool replays the persisted domain event log to
// reconstitute the order state at every lifecycle step.
//
// Use cases:
//   - Time-travel debugging: see the order state after each event
//   - Corruption recovery: works when the broker API is unreachable
//   - Regulatory audit: prove the order lifecycle from the event log
//     independently of broker state
//
// This is the first production caller of
// eventsourcing.LoadOrderFromEvents — it turns the EventStore from a
// write-only audit log into a read-side source of truth.
type GetOrderHistoryReconstitutedTool struct{}

func (*GetOrderHistoryReconstitutedTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_history_reconstituted",
		mcp.WithDescription("Reconstitute the full lifecycle of an order by replaying the append-only domain event log. Returns one state snapshot per event plus final state. Use for time-travel debugging, corruption recovery, and regulatory audit independent of broker state. Returns Found=false if no events have been persisted for this order ID."),
		mcp.WithTitleAnnotation("Get Order History (Reconstituted)"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("order_id",
			mcp.Description("ID of the order aggregate to replay from the domain event log"),
			mcp.Required(),
		),
	)
}

func (*GetOrderHistoryReconstitutedTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_history_reconstituted")
		p := NewArgParser(request.GetArguments())

		if err := p.Required("order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		orderID := p.String("order_id", "")

		return handler.WithSession(ctx, "get_order_history_reconstituted", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetOrderHistoryReconstitutedQuery{
				Email:   session.Email,
				OrderID: orderID,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to reconstitute order history: %s", err.Error())), nil
			}
			res, ok := raw.(cqrs.OrderHistoryResult)
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("unexpected query result type %T", raw)), nil
			}
			return handler.MarshalResponse(res, "get_order_history_reconstituted")
		})
	}
}

func init() { RegisterInternalTool(&GetOrderHistoryReconstitutedTool{}) }
