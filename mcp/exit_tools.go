package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// ClosePositionTool closes a single position by placing an opposite MARKET order.
type ClosePositionTool struct{}

func (*ClosePositionTool) Tool() mcp.Tool {
	return mcp.NewTool("close_position",
		mcp.WithDescription("Close a single open position by placing an opposite MARKET order. Specify the instrument in exchange:tradingsymbol format."),
		mcp.WithTitleAnnotation("Close Position"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("instrument",
			mcp.Description("Instrument in exchange:tradingsymbol format (e.g. 'NSE:INFY')"),
			mcp.Required(),
		),
		mcp.WithString("product",
			mcp.Description("Product type filter: MIS, CNC, or NRML. If omitted, closes the first matching position regardless of product."),
		),
	)
}

func (*ClosePositionTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "close_position")

		args := request.GetArguments()
		p := NewArgParser(args)
		if err := p.Required("instrument"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instrumentID := p.String("instrument", "")
		productFilter := strings.ToUpper(p.String("product", ""))

		parts := strings.SplitN(instrumentID, ":", 2)
		if len(parts) != 2 {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid instrument format: %s (expected exchange:symbol)", instrumentID)), nil
		}
		exchange := parts[0]
		symbol := parts[1]

		// Request user confirmation via elicitation.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("close_position", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "close_position", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		return handler.WithSession(ctx, "close_position", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Dispatch through CommandBus so ClosePositionUseCase runs under the
			// shared pipeline. The session-pinned broker client rides on ctx so
			// the handler-side resolver reuses it without another lookup.
			cmdCtx := kc.WithBroker(ctx, session.Broker)
			raw, err := manager.CommandBus().DispatchWithResult(cmdCtx, cqrs.ClosePositionCommand{
				Email:         session.Email,
				Exchange:      exchange,
				Symbol:        symbol,
				ProductFilter: productFilter,
			})
			if err != nil {
				handler.manager.Logger.Error("Failed to close position", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("close_position: %s", err.Error())), nil
			}
			result, _ := raw.(*usecases.ClosePositionResult)
			if result == nil {
				return mcp.NewToolResultError("close_position: unexpected nil result"), nil
			}

			return handler.MarshalResponse(map[string]any{
				"message":      fmt.Sprintf("Position closed: %s %s %d x %s", result.Direction, instrumentID, result.Quantity, result.Product),
				"order_id":     result.OrderID,
				"instrument":   result.Instrument,
				"quantity":     result.Quantity,
				"direction":    result.Direction,
				"product":      result.Product,
				"position_pnl": result.PositionPnL,
			}, "close_position")
		})
	}
}

type CloseAllPositionsTool struct{}

func (*CloseAllPositionsTool) Tool() mcp.Tool {
	return mcp.NewTool("close_all_positions",
		mcp.WithDescription("Exit ALL open positions by placing MARKET orders in the opposite direction. Use in emergencies or end-of-day cleanup. Optionally filter by product type."),
		mcp.WithTitleAnnotation("Close All Positions"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("product", mcp.Description("Filter by product type: MIS, CNC, NRML, or ALL"), mcp.DefaultString("ALL")),
		mcp.WithBoolean("confirm", mcp.Description("Must be true to execute. Safety check."), mcp.Required()),
	)
}

// closeResult holds the outcome for a single position close attempt.
type closeResult struct {
	Tradingsymbol string `json:"tradingsymbol"`
	Exchange      string `json:"exchange"`
	Quantity      int    `json:"quantity"`
	Direction     string `json:"direction"`
	OrderID       string `json:"order_id,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (*CloseAllPositionsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "close_all_positions")
		args := request.GetArguments()
		p := NewArgParser(args)

		// Safety: confirm must be true
		confirm := p.Bool("confirm", false)
		if !confirm {
			return mcp.NewToolResultError("Safety check failed: 'confirm' must be true to close all positions. This is a destructive operation."), nil
		}

		// Request user confirmation via elicitation (in addition to the confirm param).
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("close_all_positions", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "close_all_positions", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		productFilter := p.String("product", "ALL")

		return handler.WithSession(ctx, "close_all_positions", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Dispatch through CommandBus so CloseAllPositionsUseCase runs under
			// the shared pipeline. Session-pinned broker client rides on ctx.
			cmdCtx := kc.WithBroker(ctx, session.Broker)
			raw, err := manager.CommandBus().DispatchWithResult(cmdCtx, cqrs.CloseAllPositionsCommand{
				Email:         session.Email,
				ProductFilter: productFilter,
			})
			if err != nil {
				handler.manager.Logger.Error("Failed to close all positions", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("close_all_positions: %s", err.Error())), nil
			}
			result, _ := raw.(*usecases.CloseAllResult)
			if result == nil {
				return mcp.NewToolResultError("close_all_positions: unexpected nil result"), nil
			}

			if result.Total == 0 {
				return handler.MarshalResponse(map[string]any{
					"message":        "No open positions to close",
					"product_filter": result.ProductFilter,
				}, "close_all_positions")
			}

			// Convert use case results to the MCP response format.
			var results []closeResult
			for _, r := range result.Results {
				results = append(results, closeResult{
					Tradingsymbol: r.Tradingsymbol,
					Exchange:      r.Exchange,
					Quantity:      r.Quantity,
					Direction:     r.Direction,
					OrderID:       r.OrderID,
					Error:         r.Error,
				})
			}

			return handler.MarshalResponse(map[string]any{
				"message":        fmt.Sprintf("Closed %d/%d positions", result.SuccessCount, result.Total),
				"product_filter": result.ProductFilter,
				"success_count":  result.SuccessCount,
				"error_count":    result.ErrorCount,
				"total":          result.Total,
				"results":        results,
			}, "close_all_positions")
		})
	}
}
