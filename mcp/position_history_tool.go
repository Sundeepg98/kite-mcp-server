package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// GetPositionHistoryReconstitutedTool exposes event-sourced position
// lifecycle reconstitution as an MCP tool. Completes the reconstitution
// trio alongside get_order_history_reconstituted and
// get_alert_history_reconstituted.
//
// Positions have no broker-assigned unique ID — Kite's Position struct
// doesn't expose an "opening order" field — so this tool keys on the
// natural tuple (email, exchange, symbol, product). A single aggregate
// may contain multiple open→close cycles if the user has repeatedly
// traded the same instrument+product; snapshots walk the full history so
// callers can render lifecycle boundaries.
//
// First production caller of eventsourcing.LoadPositionFromEvents.
type GetPositionHistoryReconstitutedTool struct{}

func (*GetPositionHistoryReconstitutedTool) Tool() mcp.Tool {
	return mcp.NewTool("get_position_history_reconstituted",
		mcp.WithDescription("Reconstitute the full lifecycle of a position (open → close cycles) by replaying the append-only domain event log. Keyed by (exchange, tradingsymbol, product) for the caller's email. Returns one state snapshot per event plus final aggregate state. Use for intraday position replay, tax-lot audit, and regulatory proof of trade history. Returns Found=false if no events have been persisted for this position tuple."),
		mcp.WithTitleAnnotation("Get Position History (Reconstituted)"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("exchange",
			mcp.Description("Exchange, e.g. NSE, BSE, NFO"),
			mcp.Required(),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol, e.g. RELIANCE, INFY"),
			mcp.Required(),
		),
		mcp.WithString("product",
			mcp.Description("Product code: CNC (delivery), MIS (intraday), NRML (F&O carry-forward)"),
			mcp.Required(),
		),
	)
}

func (*GetPositionHistoryReconstitutedTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_position_history_reconstituted")
		p := NewArgParser(request.GetArguments())

		if err := p.Required("exchange", "tradingsymbol", "product"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		exchange := p.String("exchange", "")
		tradingsymbol := p.String("tradingsymbol", "")
		product := p.String("product", "")

		return handler.WithSession(ctx, "get_position_history_reconstituted", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPositionHistoryReconstitutedQuery{
				Email:         session.Email,
				Exchange:      exchange,
				Tradingsymbol: tradingsymbol,
				Product:       product,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to reconstitute position history: %s", err.Error())), nil
			}
			res, ok := raw.(cqrs.PositionHistoryResult)
			if !ok {
				return mcp.NewToolResultError(fmt.Sprintf("unexpected query result type %T", raw)), nil
			}
			return handler.MarshalResponse(res, "get_position_history_reconstituted")
		})
	}
}
