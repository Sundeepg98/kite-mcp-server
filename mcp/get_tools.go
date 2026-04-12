package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

type ProfileTool struct{}

func (*ProfileTool) Tool() mcp.Tool {
	return mcp.NewTool("get_profile",
		mcp.WithDescription("Retrieve the user's profile information, including user ID, name, email, and account details like products orders, and exchanges available to the user. Use this to get basic user details."),
		mcp.WithTitleAnnotation("Get Profile"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

func (*ProfileTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return SimpleToolHandler(manager, "get_profile", func(session *kc.KiteSessionData) (interface{}, error) {
		return manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetProfileQuery{Email: session.Email})
	})
}

type MarginsTool struct{}

func (*MarginsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_margins",
		mcp.WithDescription("Get margins"),
		mcp.WithTitleAnnotation("Get Margins"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

func (*MarginsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return SimpleToolHandler(manager, "get_margins", func(session *kc.KiteSessionData) (interface{}, error) {
		return manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetMarginsQuery{Email: session.Email})
	})
}

type HoldingsTool struct{}

func (*HoldingsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_holdings",
		mcp.WithDescription("Get holdings for the current user. Supports pagination for large datasets."),
		mcp.WithTitleAnnotation("Get Holdings"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of holdings to return. If not specified, returns all holdings. When specified, response includes pagination metadata."),
		),
	)
}

func (*HoldingsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_holdings", func(session *kc.KiteSessionData) ([]interface{}, error) {
		// Phase 2j: dispatch through CQRS query bus (handler registered in app/wire_bus.go).
		raw, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetPortfolioQuery{Email: session.Email})
		if err != nil {
			return nil, err
		}
		portfolio := raw.(*usecases.PortfolioResult)

		// Convert to []interface{} for generic pagination
		result := make([]interface{}, len(portfolio.Holdings))
		for i, holding := range portfolio.Holdings {
			result[i] = holding
		}
		return result, nil
	})
}

type PositionsTool struct{}

func (*PositionsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_positions",
		mcp.WithDescription("Get current positions. Returns net positions by default (use position_type='day' for intraday). Supports pagination for large datasets."),
		mcp.WithTitleAnnotation("Get Positions"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("position_type",
			mcp.Description("Type of positions to return: 'net' (default, end-of-day view) or 'day' (intraday view)"),
			mcp.DefaultString("net"),
			mcp.Enum("net", "day"),
		),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of positions to return. If not specified, returns all positions. When specified, response includes pagination metadata."),
		),
	)
}

func (*PositionsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandlerWithArgs(manager, "get_positions", func(session *kc.KiteSessionData, args map[string]any) ([]interface{}, error) {
		raw, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetPortfolioQuery{Email: session.Email})
		if err != nil {
			return nil, err
		}
		portfolio := raw.(*usecases.PortfolioResult)

		p := NewArgParser(args)
		posType := p.String("position_type", "net")

		var source []broker.Position
		switch posType {
		case "day":
			source = portfolio.Positions.Day
		default:
			source = portfolio.Positions.Net
		}

		result := make([]interface{}, len(source))
		for i, pos := range source {
			result[i] = pos
		}
		return result, nil
	})
}

type TradesTool struct{}

func (*TradesTool) Tool() mcp.Tool {
	return mcp.NewTool("get_trades",
		mcp.WithDescription("Get trading history. Supports pagination for large datasets."),
		mcp.WithTitleAnnotation("Get Trades"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of trades to return. If not specified, returns all trades. When specified, response includes pagination metadata."),
		),
	)
}

func (*TradesTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_trades", func(session *kc.KiteSessionData) ([]interface{}, error) {
		raw, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetTradesQuery{Email: session.Email})
		if err != nil {
			return nil, err
		}
		trades := raw.([]broker.Trade)

		result := make([]interface{}, len(trades))
		for i, trade := range trades {
			result[i] = trade
		}
		return result, nil
	})
}

type OrdersTool struct{}

func (*OrdersTool) Tool() mcp.Tool {
	return mcp.NewTool("get_orders",
		mcp.WithDescription("Get all orders. Supports pagination for large datasets."),
		mcp.WithTitleAnnotation("Get Orders"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of orders to return. If not specified, returns all orders. When specified, response includes pagination metadata."),
		),
	)
}

func (*OrdersTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_orders", func(session *kc.KiteSessionData) ([]interface{}, error) {
		raw, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetOrdersQuery{Email: session.Email})
		if err != nil {
			return nil, err
		}
		orders := raw.([]broker.Order)

		result := make([]interface{}, len(orders))
		for i, order := range orders {
			result[i] = order
		}
		return result, nil
	})
}

type GTTOrdersTool struct{}

func (*GTTOrdersTool) Tool() mcp.Tool {
	return mcp.NewTool("get_gtts",
		mcp.WithDescription("Get all active GTT orders. Supports pagination for large datasets."),
		mcp.WithTitleAnnotation("Get GTT Orders"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("from",
			mcp.Description("Starting index for pagination (0-based). Default: 0"),
		),
		mcp.WithNumber("limit",
			mcp.Description("Maximum number of GTT orders to return. If not specified, returns all GTT orders. When specified, response includes pagination metadata."),
		),
	)
}

func (*GTTOrdersTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	return PaginatedToolHandler(manager, "get_gtts", func(session *kc.KiteSessionData) ([]interface{}, error) {
		raw, err := manager.QueryBus().DispatchWithResult(context.Background(), cqrs.GetGTTsQuery{Email: session.Email})
		if err != nil {
			return nil, err
		}
		gtts := raw.([]broker.GTTOrder)

		result := make([]interface{}, len(gtts))
		for i, gtt := range gtts {
			result[i] = gtt
		}
		return result, nil
	})
}

type OrderTradesTool struct{}

func (*OrderTradesTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_trades",
		mcp.WithDescription("Get trades for a specific order"),
		mcp.WithTitleAnnotation("Get Order Trades"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("order_id",
			mcp.Description("ID of the order to fetch trades for"),
			mcp.Required(),
		),
	)
}

func (*OrderTradesTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_trades")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		orderID := p.String("order_id", "")

		return handler.WithSession(ctx, "get_order_trades", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetOrderTradesQuery{Email: session.Email, OrderID: orderID})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get order trades: %s", err.Error())), nil
			}
			orderTrades := raw.([]broker.Trade)

			return handler.MarshalResponse(orderTrades, "get_order_trades")
		})
	}
}

type OrderHistoryTool struct{}

func (*OrderHistoryTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_history",
		mcp.WithDescription("Get order history for a specific order"),
		mcp.WithTitleAnnotation("Get Order History"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("order_id",
			mcp.Description("ID of the order to fetch history for"),
			mcp.Required(),
		),
	)
}

func (*OrderHistoryTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_history")
		p := NewArgParser(request.GetArguments())

		// Validate required parameters
		if err := p.Required("order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		orderID := p.String("order_id", "")

		return handler.WithSession(ctx, "get_order_history", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetOrderHistoryQuery{Email: session.Email, OrderID: orderID})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get order history: %s", err.Error())), nil
			}
			orderHistory := raw.([]broker.Order)

			return handler.MarshalResponse(orderHistory, "get_order_history")
		})
	}
}
