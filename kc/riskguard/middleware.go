package riskguard

import (
	"context"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Middleware returns an MCP tool handler middleware that runs risk checks
// before order tools execute. Non-order tools pass through immediately.
func Middleware(guard *Guard) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			toolName := request.Params.Name

			if !IsOrderTool(toolName) {
				return next(ctx, request)
			}

			email := oauth.EmailFromContext(ctx)
			if email == "" {
				return next(ctx, request) // no auth context — fail open
			}

			args := request.GetArguments()
			req := OrderCheckRequest{
				Email:           email,
				ToolName:        toolName,
				Exchange:        safeString(args["exchange"]),
				Tradingsymbol:   safeString(args["tradingsymbol"]),
				TransactionType: safeString(args["transaction_type"]),
				Quantity:        safeInt(args["quantity"]),
				// Wire-format boundary: tool args carry float prices over JSON.
				// Reconstruct an INR Money on entry to the riskguard pipeline.
				Price:     domain.NewINR(safeFloat(args["price"])),
				OrderType: safeString(args["order_type"]),
				// Confirmed=true is the user-facing ACK that satisfies the
				// RequireConfirmAllOrders gate. Populated from the tool's
				// `confirm` boolean arg (same convention as elicitation).
				Confirmed: safeBool(args["confirm"]),
				// ClientOrderID is the optional idempotency key (Alpaca-style).
				// When supplied, the same key within 15 min is rejected as a
				// duplicate — primary defence against mcp-remote retry storms.
				ClientOrderID: safeString(args["client_order_id"]),
				// Variety threads through so checkMarketHours can see "amo"
				// and bypass the [09:15, 15:30) IST market-hours block.
				Variety: safeString(args["variety"]),
			}

			// For SL/SL-M, use trigger_price if price is 0
			if req.Price.IsZero() {
				req.Price = domain.NewINR(safeFloat(args["trigger_price"]))
			}

			result := guard.CheckOrderCtx(ctx, req)
			if !result.Allowed {
				if guard.logger != nil {
					guard.logger.Warn(ctx, "Order blocked by riskguard",
						"email", email, "tool", toolName, "reason", result.Reason, "message", result.Message)
				}
				return gomcp.NewToolResultError(
					"ORDER BLOCKED [" + string(result.Reason) + "]: " + result.Message,
				), nil
			}

			// Execute the tool
			response, err := next(ctx, request)

			// Record successful order for all tracking (daily count, rate, duplicates, value)
			if err == nil && response != nil && !response.IsError {
				guard.RecordOrder(email, req)
			}

			return response, err
		}
	}
}

func safeString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func safeInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

func safeFloat(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

func safeBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}
