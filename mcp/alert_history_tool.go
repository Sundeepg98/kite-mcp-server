package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetAlertHistoryReconstitutedTool exposes event-sourced alert lifecycle
// reconstitution as an MCP tool. Solves a real user-observed pain: Telegram
// DM delivery is lossy, and until this tool existed there was no independent
// way for a user (or a family admin investigating "why didn't my wife's
// alert fire yesterday") to prove an alert had actually triggered
// server-side. The persisted event log is the immutable source of truth.
//
// Complements get_order_history_reconstituted — same pattern, replays
// AlertCreatedEvent → AlertTriggeredEvent → AlertDeletedEvent through
// LoadAlertFromEvents.
type GetAlertHistoryReconstitutedTool struct{}

func (*GetAlertHistoryReconstitutedTool) Tool() mcp.Tool {
	return mcp.NewTool("get_alert_history_reconstituted",
		mcp.WithDescription("Reconstitute the full lifecycle of a price alert by replaying the append-only domain event log. Returns one state snapshot per event plus final aggregate state. Use for proving an alert fired when Telegram delivery was lost, family-admin investigations, or compliance audit. Returns Found=false if no events have been persisted for this alert ID."),
		mcp.WithTitleAnnotation("Get Alert History (Reconstituted)"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("alert_id",
			mcp.Description("ID of the alert aggregate to replay from the domain event log"),
			mcp.Required(),
		),
	)
}

func (*GetAlertHistoryReconstitutedTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_alert_history_reconstituted")
		p := NewArgParser(request.GetArguments())

		if err := p.Required("alert_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		alertID := p.String("alert_id", "")

		return handler.WithSession(ctx, "get_alert_history_reconstituted", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetAlertHistoryReconstitutedQuery{
				Email:   session.Email,
				AlertID: alertID,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to reconstitute alert history: %s", err.Error())), nil
			}
			res, ok := raw.(cqrs.AlertHistoryResult)
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("unexpected query result type %T", raw)), nil
			}
			return handler.MarshalResponse(res, "get_alert_history_reconstituted")
		})
	}
}
