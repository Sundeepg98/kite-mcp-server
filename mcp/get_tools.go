package mcp

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

type ProfileTool struct{}

func (*ProfileTool) Definition() *mcp.Tool {
	return NewTool("get_profile",
		"Retrieve the user's profile information, including user ID, name, email, and account details like products orders, and exchanges available to the user. Use this to get basic user details.",
		nil,
	)
}

func (*ProfileTool) Handler(manager *kc.Manager) ToolHandler {
	return SimpleToolHandler(manager, "get_profile", func(client *kiteconnect.Client) (interface{}, error) {
		return client.GetUserProfile()
	})
}

type MarginsTool struct{}

func (*MarginsTool) Definition() *mcp.Tool {
	return NewTool("get_margins", "Get margins", nil)
}

func (*MarginsTool) Handler(manager *kc.Manager) ToolHandler {
	return SimpleToolHandler(manager, "get_margins", func(client *kiteconnect.Client) (interface{}, error) {
		return client.GetUserMargins()
	})
}

type HoldingsTool struct{}

var holdingsSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"type": {
			"type": "string",
			"description": "Type of holdings data to retrieve. 'full' returns detailed holdings with pagination, 'summary' returns aggregated summary data, 'compact' returns compact holdings with pagination",
			"default": "full",
			"enum": ["full", "summary", "compact"]
		},
		"from": {
			"type": "number",
			"description": "Starting index for pagination (0-based). Default: 0"
		},
		"limit": {
			"type": "number",
			"description": "Maximum number of holdings to return. If not specified, returns all holdings. When specified, response includes pagination metadata. Only applies to 'full' and 'compact' types"
		}
	}
}`)

func (*HoldingsTool) Definition() *mcp.Tool {
	return NewTool("get_holdings",
		"Get holdings for the current user. Supports pagination for large datasets.",
		holdingsSchema,
	)
}

func (*HoldingsTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		holdingsType := SafeAssertString(args["type"], "full")

		return handler.WithKiteClient(request, "get_holdings", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			switch holdingsType {
			case "summary":
				summary, err := client.GetHoldingsSummary()
				if err != nil {
					return nil, err
				}
				return handler.MarshalResponse(summary, "get_holdings")

			case "compact":
				compactHoldings, err := client.GetHoldingsCompact()
				if err != nil {
					return nil, err
				}
				result := make([]interface{}, len(compactHoldings))
				for i, holding := range compactHoldings {
					result[i] = holding
				}
				params := ParsePaginationParams(args)
				originalLength := len(result)
				paginatedData := ApplyPagination(result, params)
				var responseData interface{}
				if params.Limit > 0 {
					responseData = CreatePaginatedResponse(result, paginatedData, params, originalLength)
				} else {
					responseData = paginatedData
				}
				return handler.MarshalResponse(responseData, "get_holdings")

			default: // "full" or any other value
				holdings, err := client.GetHoldings()
				if err != nil {
					return nil, err
				}
				result := make([]interface{}, len(holdings))
				for i, holding := range holdings {
					result[i] = holding
				}
				params := ParsePaginationParams(args)
				originalLength := len(result)
				paginatedData := ApplyPagination(result, params)
				var responseData interface{}
				if params.Limit > 0 {
					responseData = CreatePaginatedResponse(result, paginatedData, params, originalLength)
				} else {
					responseData = paginatedData
				}
				return handler.MarshalResponse(responseData, "get_holdings")
			}
		})
	}
}

type PositionsTool struct{}

var paginationSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"from": {
			"type": "number",
			"description": "Starting index for pagination (0-based). Default: 0"
		},
		"limit": {
			"type": "number",
			"description": "Maximum number of items to return. If not specified, returns all items. When specified, response includes pagination metadata."
		}
	}
}`)

func (*PositionsTool) Definition() *mcp.Tool {
	return NewTool("get_positions",
		"Get current positions. Supports pagination for large datasets.",
		paginationSchema,
	)
}

func (*PositionsTool) Handler(manager *kc.Manager) ToolHandler {
	return PaginatedToolHandler(manager, "get_positions", func(client *kiteconnect.Client) ([]interface{}, error) {
		positions, err := client.GetPositions()
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(positions.Day)+len(positions.Net))
		idx := 0
		for _, pos := range positions.Day {
			result[idx] = pos
			idx++
		}
		for _, pos := range positions.Net {
			result[idx] = pos
			idx++
		}
		return result, nil
	})
}

type TradesTool struct{}

func (*TradesTool) Definition() *mcp.Tool {
	return NewTool("get_trades",
		"Get trading history. Supports pagination for large datasets.",
		paginationSchema,
	)
}

func (*TradesTool) Handler(manager *kc.Manager) ToolHandler {
	return PaginatedToolHandler(manager, "get_trades", func(client *kiteconnect.Client) ([]interface{}, error) {
		trades, err := client.GetTrades()
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(trades))
		for i, trade := range trades {
			result[i] = trade
		}
		return result, nil
	})
}

type OrdersTool struct{}

func (*OrdersTool) Definition() *mcp.Tool {
	return NewTool("get_orders",
		"Get all orders. Supports pagination for large datasets.",
		paginationSchema,
	)
}

func (*OrdersTool) Handler(manager *kc.Manager) ToolHandler {
	return PaginatedToolHandler(manager, "get_orders", func(client *kiteconnect.Client) ([]interface{}, error) {
		orders, err := client.GetOrders()
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(orders))
		for i, order := range orders {
			result[i] = order
		}
		return result, nil
	})
}

type GTTOrdersTool struct{}

func (*GTTOrdersTool) Definition() *mcp.Tool {
	return NewTool("get_gtts",
		"Get all active GTT orders. Supports pagination for large datasets.",
		paginationSchema,
	)
}

func (*GTTOrdersTool) Handler(manager *kc.Manager) ToolHandler {
	return PaginatedToolHandler(manager, "get_gtts", func(client *kiteconnect.Client) ([]interface{}, error) {
		gttBook, err := client.GetGTTs()
		if err != nil {
			return nil, err
		}
		result := make([]interface{}, len(gttBook))
		for i, gtt := range gttBook {
			result[i] = gtt
		}
		return result, nil
	})
}

type OrderTradesTool struct{}

var orderIDSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"order_id": {
			"type": "string",
			"description": "ID of the order"
		}
	},
	"required": ["order_id"]
}`)

func (*OrderTradesTool) Definition() *mcp.Tool {
	return NewTool("get_order_trades",
		"Get trades for a specific order",
		orderIDSchema,
	)
}

func (*OrderTradesTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "order_id"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		orderID := SafeAssertString(args["order_id"], "")

		return handler.WithKiteClient(request, "get_order_trades", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			orderTrades, err := client.GetOrderTrades(orderID)
			if err != nil {
				return NewToolResultError("Failed to get order trades"), nil
			}
			return handler.MarshalResponse(orderTrades, "get_order_trades")
		})
	}
}

type OrderHistoryTool struct{}

func (*OrderHistoryTool) Definition() *mcp.Tool {
	return NewTool("get_order_history",
		"Get order history for a specific order",
		orderIDSchema,
	)
}

func (*OrderHistoryTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "order_id"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		orderID := SafeAssertString(args["order_id"], "")

		return handler.WithKiteClient(request, "get_order_history", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			orderHistory, err := client.GetOrderHistory(orderID)
			if err != nil {
				return NewToolResultError("Failed to get order history"), nil
			}
			return handler.MarshalResponse(orderHistory, "get_order_history")
		})
	}
}
