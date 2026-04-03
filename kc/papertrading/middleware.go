package papertrading

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// writeTools are tools that mutate state and should be intercepted in paper mode.
var writeTools = map[string]bool{
	"place_order":      true,
	"modify_order":     true,
	"cancel_order":     true,
	"close_position":   true,
	"close_all_positions": true,
	"place_gtt_order":  true,
	"modify_gtt_order": true,
	"delete_gtt_order": true,
}

// readTools are tools that return data and should be intercepted in paper mode.
var readTools = map[string]bool{
	"get_holdings":      true,
	"get_positions":     true,
	"get_orders":        true,
	"get_margins":       true,
	"get_order_history": true,
	"get_trades":        true,
}

// Middleware returns MCP tool handler middleware that intercepts order and
// portfolio tools when the user has paper trading enabled. Non-paper users
// and unrecognised tools pass through to the real handler.
func Middleware(engine *PaperEngine) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" || !engine.IsEnabled(email) {
				return next(ctx, request)
			}

			toolName := request.Params.Name
			args := request.GetArguments()

			if writeTools[toolName] {
				return handleWrite(engine, email, toolName, args)
			}
			if readTools[toolName] {
				return handleRead(engine, email, toolName, args)
			}

			// Unknown tool — pass through.
			return next(ctx, request)
		}
	}
}

// handleWrite routes write tools to the paper engine.
func handleWrite(engine *PaperEngine, email, toolName string, args map[string]any) (*gomcp.CallToolResult, error) {
	switch toolName {
	case "place_order":
		return paperResult(engine.PlaceOrder(email, args))

	case "modify_order":
		orderID := safeStr(args["order_id"])
		return paperResult(engine.ModifyOrder(email, orderID, args))

	case "cancel_order":
		orderID := safeStr(args["order_id"])
		return paperResult(engine.CancelOrder(email, orderID))

	case "close_position":
		return handleClosePosition(engine, email, args)

	case "close_all_positions":
		return handleCloseAllPositions(engine, email)

	case "place_gtt_order", "modify_gtt_order", "delete_gtt_order":
		return paperTextResult("GTT not supported in paper mode"), nil

	default:
		return nil, fmt.Errorf("unhandled write tool %q", toolName)
	}
}

// handleRead routes read tools to the paper engine.
func handleRead(engine *PaperEngine, email, toolName string, args map[string]any) (*gomcp.CallToolResult, error) {
	switch toolName {
	case "get_holdings":
		return paperResult(engine.GetHoldings(email))

	case "get_positions":
		return paperResult(engine.GetPositions(email))

	case "get_orders":
		return paperResult(engine.GetOrders(email))

	case "get_margins":
		return paperResult(engine.GetMargins(email))

	case "get_order_history":
		orderID := safeStr(args["order_id"])
		order, err := engine.store.GetOrder(orderID)
		if err != nil {
			return gomcp.NewToolResultError("[PAPER] " + err.Error()), nil
		}
		return paperResult(orderToMap(order), nil)

	case "get_trades":
		return handleGetTrades(engine, email)

	default:
		return nil, fmt.Errorf("unhandled read tool %q", toolName)
	}
}

// handleClosePosition computes an opposite order from the current position and places it.
func handleClosePosition(engine *PaperEngine, email string, args map[string]any) (*gomcp.CallToolResult, error) {
	exchange := safeStr(args["exchange"])
	tradingsymbol := safeStr(args["tradingsymbol"])
	product := safeStr(args["product"])

	positions, err := engine.store.GetPositions(email)
	if err != nil {
		return gomcp.NewToolResultError("[PAPER] " + err.Error()), nil
	}

	for _, p := range positions {
		if p.Exchange == exchange && p.Tradingsymbol == tradingsymbol && (product == "" || p.Product == product) {
			txnType := "SELL"
			qty := p.Quantity
			if qty < 0 {
				txnType = "BUY"
				qty = -qty
			}
			if qty == 0 {
				return paperTextResult("Position already flat"), nil
			}
			return paperResult(engine.PlaceOrder(email, map[string]any{
				"exchange":         p.Exchange,
				"tradingsymbol":    p.Tradingsymbol,
				"transaction_type": txnType,
				"order_type":       "MARKET",
				"product":          p.Product,
				"quantity":         qty,
			}))
		}
	}
	return gomcp.NewToolResultError("[PAPER] No matching position found"), nil
}

// handleCloseAllPositions closes every open position.
func handleCloseAllPositions(engine *PaperEngine, email string) (*gomcp.CallToolResult, error) {
	positions, err := engine.store.GetPositions(email)
	if err != nil {
		return gomcp.NewToolResultError("[PAPER] " + err.Error()), nil
	}
	if len(positions) == 0 {
		return paperTextResult("No open positions"), nil
	}

	var results []map[string]any
	for _, p := range positions {
		txnType := "SELL"
		qty := p.Quantity
		if qty < 0 {
			txnType = "BUY"
			qty = -qty
		}
		if qty == 0 {
			continue
		}
		res, err := engine.PlaceOrder(email, map[string]any{
			"exchange":         p.Exchange,
			"tradingsymbol":    p.Tradingsymbol,
			"transaction_type": txnType,
			"order_type":       "MARKET",
			"product":          p.Product,
			"quantity":         qty,
		})
		if err != nil {
			results = append(results, map[string]any{
				"tradingsymbol": p.Tradingsymbol,
				"error":         err.Error(),
			})
		} else {
			results = append(results, map[string]any{
				"tradingsymbol": p.Tradingsymbol,
				"result":        res,
			})
		}
	}
	return paperResult(results, nil)
}

// handleGetTrades returns filled orders formatted as trades.
func handleGetTrades(engine *PaperEngine, email string) (*gomcp.CallToolResult, error) {
	orders, err := engine.store.GetOrders(email)
	if err != nil {
		return gomcp.NewToolResultError("[PAPER] " + err.Error()), nil
	}

	var trades []map[string]any
	for _, o := range orders {
		if o.Status != "COMPLETE" {
			continue
		}
		trades = append(trades, map[string]any{
			"trade_id":         "T_" + o.OrderID,
			"order_id":         o.OrderID,
			"exchange":         o.Exchange,
			"tradingsymbol":    o.Tradingsymbol,
			"transaction_type": o.TransactionType,
			"product":          o.Product,
			"quantity":         o.FilledQuantity,
			"average_price":    o.AveragePrice,
			"fill_timestamp":   o.FilledAt.Format("2006-01-02 15:04:05"),
		})
	}
	return paperResult(trades, nil)
}

// paperResult wraps an engine response into a [PAPER]-prefixed MCP result.
func paperResult(data any, err error) (*gomcp.CallToolResult, error) {
	if err != nil {
		return gomcp.NewToolResultError("[PAPER] " + err.Error()), nil
	}
	jsonBytes, jErr := json.Marshal(data)
	if jErr != nil {
		return gomcp.NewToolResultError("[PAPER] marshal error: " + jErr.Error()), nil
	}
	text := "[PAPER] " + string(jsonBytes)
	return gomcp.NewToolResultStructured(data, text), nil
}

// paperTextResult returns a simple text result with the [PAPER] prefix.
func paperTextResult(msg string) *gomcp.CallToolResult {
	return gomcp.NewToolResultText("[PAPER] " + msg)
}

func safeStr(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}
