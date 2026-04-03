package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

// OrderMarginsTool calculates margin required for an order before placing it.
type OrderMarginsTool struct{}

func (*OrderMarginsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_margins",
		mcp.WithDescription("Calculate margin required for an order before placing it. Use this to check if you have sufficient funds."),
		mcp.WithTitleAnnotation("Get Order Margins"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("exchange",
			mcp.Description("Exchange"),
			mcp.Required(),
			mcp.Enum("NSE", "BSE", "NFO", "BFO", "MCX"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("BUY or SELL"),
			mcp.Required(),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity"),
			mcp.Required(),
		),
		mcp.WithString("product",
			mcp.Description("Product type"),
			mcp.Required(),
			mcp.Enum("CNC", "NRML", "MIS", "MTF"),
		),
		mcp.WithString("order_type",
			mcp.Description("Order type"),
			mcp.Required(),
			mcp.Enum("MARKET", "LIMIT", "SL", "SL-M"),
		),
		mcp.WithNumber("price",
			mcp.Description("Price for LIMIT orders"),
		),
		mcp.WithNumber("trigger_price",
			mcp.Description("Trigger price for SL/SL-M orders"),
		),
		mcp.WithString("variety",
			mcp.Description("Order variety"),
			mcp.DefaultString("regular"),
			mcp.Enum("regular", "co", "amo", "iceberg"),
		),
	)
}

func (*OrderMarginsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_margins")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		orderType := SafeAssertString(args["order_type"], "")
		price := SafeAssertFloat64(args["price"], 0.0)
		triggerPrice := SafeAssertFloat64(args["trigger_price"], 0.0)

		// Validate price for LIMIT orders
		if orderType == "LIMIT" && price <= 0 {
			return mcp.NewToolResultError("price must be greater than 0 for LIMIT orders"), nil
		}
		// Validate trigger_price for SL/SL-M orders
		if (orderType == "SL" || orderType == "SL-M") && triggerPrice <= 0 {
			return mcp.NewToolResultError("trigger_price must be greater than 0 for SL/SL-M orders"), nil
		}

		param := kiteconnect.OrderMarginParam{
			Exchange:        SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
			Variety:         SafeAssertString(args["variety"], "regular"),
			Product:         SafeAssertString(args["product"], ""),
			OrderType:       orderType,
			Quantity:        SafeAssertFloat64(args["quantity"], 0),
			Price:           price,
			TriggerPrice:    triggerPrice,
		}

		return handler.WithSession(ctx, "get_order_margins", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.GetOrderMargins(kiteconnect.GetMarginParams{
				OrderParams: []kiteconnect.OrderMarginParam{param},
			})
			if err != nil {
				handler.manager.Logger.Error("Failed to get order margins", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("get_order_margins: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "get_order_margins")
		})
	}
}

// BasketMarginsTool calculates combined margin for a basket of orders.
type BasketMarginsTool struct{}

func (*BasketMarginsTool) Tool() mcp.Tool {
	return mcp.NewTool("get_basket_margins",
		mcp.WithDescription("Calculate combined margin for a basket of orders. Useful for multi-leg strategies like spreads. Shows margin benefit from hedging."),
		mcp.WithTitleAnnotation("Get Basket Margins"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("orders",
			mcp.Description("JSON array of orders, each with: exchange, tradingsymbol, transaction_type, quantity, product, order_type, price (optional), trigger_price (optional), variety (optional, defaults to 'regular')"),
			mcp.Required(),
		),
		mcp.WithBoolean("consider_positions",
			mcp.Description("Consider existing positions for margin benefit"),
		),
	)
}

func (*BasketMarginsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_basket_margins")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "orders"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		ordersJSON := SafeAssertString(args["orders"], "")
		if ordersJSON == "" {
			return mcp.NewToolResultError("orders cannot be empty"), nil
		}

		// Parse the JSON orders array
		var orderParams []kiteconnect.OrderMarginParam
		if err := json.Unmarshal([]byte(ordersJSON), &orderParams); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid orders JSON: %s", err.Error())), nil
		}

		if len(orderParams) == 0 {
			return mcp.NewToolResultError("orders array cannot be empty"), nil
		}

		// Default variety to "regular" for any order that doesn't have it set
		for i := range orderParams {
			if orderParams[i].Variety == "" {
				orderParams[i].Variety = "regular"
			}
		}

		considerPositions := SafeAssertBool(args["consider_positions"], false)

		return handler.WithSession(ctx, "get_basket_margins", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.GetBasketMargins(kiteconnect.GetBasketParams{
				OrderParams:       orderParams,
				ConsiderPositions: considerPositions,
			})
			if err != nil {
				handler.manager.Logger.Error("Failed to get basket margins", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("get_basket_margins: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "get_basket_margins")
		})
	}
}

// OrderChargesTool calculates brokerage, taxes, and charges for an order.
type OrderChargesTool struct{}

func (*OrderChargesTool) Tool() mcp.Tool {
	return mcp.NewTool("get_order_charges",
		mcp.WithDescription("Calculate brokerage, STT, stamp duty, exchange charges, and GST breakdown for orders. Useful for understanding the total cost of a trade."),
		mcp.WithTitleAnnotation("Get Order Charges"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("orders",
			mcp.Description("JSON array of orders, each with: order_id, exchange, tradingsymbol, transaction_type, quantity, average_price, product, order_type, variety"),
			mcp.Required(),
		),
	)
}

func (*OrderChargesTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_order_charges")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "orders"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		ordersJSON := SafeAssertString(args["orders"], "")
		if ordersJSON == "" {
			return mcp.NewToolResultError("orders cannot be empty"), nil
		}

		// Parse the JSON orders array
		var orderParams []kiteconnect.OrderChargesParam
		if err := json.Unmarshal([]byte(ordersJSON), &orderParams); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid orders JSON: %s", err.Error())), nil
		}

		if len(orderParams) == 0 {
			return mcp.NewToolResultError("orders array cannot be empty"), nil
		}

		return handler.WithSession(ctx, "get_order_charges", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.GetOrderCharges(kiteconnect.GetChargesParams{
				OrderParams: orderParams,
			})
			if err != nil {
				handler.manager.Logger.Error("Failed to get order charges", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("get_order_charges: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "get_order_charges")
		})
	}
}
