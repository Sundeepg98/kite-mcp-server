package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

// ClosePositionTool closes a single position by placing an opposite MARKET order.
type ClosePositionTool struct{}

func (*ClosePositionTool) Tool() mcp.Tool {
	return mcp.NewTool("close_position",
		mcp.WithDescription("Close a single open position by placing an opposite MARKET order. Specify the instrument in exchange:tradingsymbol format."),
		mcp.WithDestructiveHintAnnotation(true),
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
		if err := ValidateRequired(args, "instrument"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instrumentID := SafeAssertString(args["instrument"], "")
		productFilter := strings.ToUpper(SafeAssertString(args["product"], ""))

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
			positions, err := session.Kite.Client.GetPositions()
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch positions: %s", err.Error())), nil
			}

			// Find the matching position
			var matched *kiteconnect.Position
			for i, p := range positions.Net {
				if p.Quantity == 0 {
					continue
				}
				if strings.EqualFold(p.Exchange, exchange) && strings.EqualFold(p.Tradingsymbol, symbol) {
					if productFilter != "" && strings.ToUpper(p.Product) != productFilter {
						continue
					}
					matched = &positions.Net[i]
					break
				}
			}

			if matched == nil {
				return mcp.NewToolResultError(fmt.Sprintf("No open position found for %s", instrumentID)), nil
			}

			// Determine opposite direction
			var txnType string
			qty := int(math.Abs(float64(matched.Quantity)))
			if matched.Quantity > 0 {
				txnType = "SELL"
			} else {
				txnType = "BUY"
			}

			orderParams := kiteconnect.OrderParams{
				Exchange:         matched.Exchange,
				Tradingsymbol:    matched.Tradingsymbol,
				TransactionType:  txnType,
				Quantity:         qty,
				Product:          matched.Product,
				OrderType:        "MARKET",
				Validity:         "DAY",
				MarketProtection: kiteconnect.MarketProtectionAuto,
			}

			resp, placeErr := session.Kite.Client.PlaceOrder("regular", orderParams)
			if placeErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to close position %s: %s", instrumentID, placeErr.Error())), nil
			}

			return handler.MarshalResponse(map[string]any{
				"message":       fmt.Sprintf("Position closed: %s %s %d x %s", txnType, instrumentID, qty, matched.Product),
				"order_id":      resp.OrderID,
				"instrument":    instrumentID,
				"quantity":      qty,
				"direction":     txnType,
				"product":       matched.Product,
				"position_pnl":  matched.PnL,
			}, "close_position")
		})
	}
}

type CloseAllPositionsTool struct{}

func (*CloseAllPositionsTool) Tool() mcp.Tool {
	return mcp.NewTool("close_all_positions",
		mcp.WithDescription("Exit ALL open positions by placing MARKET orders in the opposite direction. Use in emergencies or end-of-day cleanup. Optionally filter by product type."),
		mcp.WithDestructiveHintAnnotation(true),
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

		// Safety: confirm must be true
		confirm := SafeAssertBool(args["confirm"], false)
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

		productFilter := strings.ToUpper(SafeAssertString(args["product"], "ALL"))

		return handler.WithSession(ctx, "close_all_positions", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			positions, err := session.Kite.Client.GetPositions()
			if err != nil {
				handler.manager.Logger.Error("Failed to fetch positions", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("close_all_positions: failed to fetch positions: %s", err.Error())), nil
			}

			// Filter to positions with non-zero Quantity (net positions)
			var toClose []kiteconnect.Position
			for _, p := range positions.Net {
				if p.Quantity == 0 {
					continue
				}
				if productFilter != "ALL" && strings.ToUpper(p.Product) != productFilter {
					continue
				}
				toClose = append(toClose, p)
			}

			if len(toClose) == 0 {
				return handler.MarshalResponse(map[string]any{
					"message":        "No open positions to close",
					"product_filter": productFilter,
				}, "close_all_positions")
			}

			var results []closeResult
			successCount := 0
			errorCount := 0

			for _, p := range toClose {
				// Determine opposite direction
				var txnType string
				qty := int(math.Abs(float64(p.Quantity)))
				if p.Quantity > 0 {
					txnType = "SELL"
				} else {
					txnType = "BUY"
				}

				orderParams := kiteconnect.OrderParams{
					Exchange:         p.Exchange,
					Tradingsymbol:    p.Tradingsymbol,
					TransactionType:  txnType,
					Quantity:         qty,
					Product:          p.Product,
					OrderType:        "MARKET",
					Validity:         "DAY",
					MarketProtection: kiteconnect.MarketProtectionAuto,
				}

				resp, placeErr := session.Kite.Client.PlaceOrder("regular", orderParams)
				r := closeResult{
					Tradingsymbol: p.Tradingsymbol,
					Exchange:      p.Exchange,
					Quantity:      qty,
					Direction:     txnType,
				}
				if placeErr != nil {
					r.Error = placeErr.Error()
					errorCount++
					handler.manager.Logger.Error("Failed to close position",
						"symbol", p.Tradingsymbol, "error", placeErr)
				} else {
					r.OrderID = resp.OrderID
					successCount++
				}
				results = append(results, r)
			}

			return handler.MarshalResponse(map[string]any{
				"message":        fmt.Sprintf("Closed %d/%d positions", successCount, len(toClose)),
				"product_filter": productFilter,
				"success_count":  successCount,
				"error_count":    errorCount,
				"total":          len(toClose),
				"results":        results,
			}, "close_all_positions")
		})
	}
}
