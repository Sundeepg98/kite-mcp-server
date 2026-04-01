package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

type PlaceOrderTool struct{}

func (*PlaceOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("place_order",
		mcp.WithDescription("Place an order"),
		mcp.WithString("variety",
			mcp.Description("Order variety"),
			mcp.Required(),
			mcp.DefaultString("regular"),
			mcp.Enum("regular", "co", "amo", "iceberg", "auction"),
		),
		mcp.WithString("exchange",
			mcp.Description("The exchange to which the order should be placed"),
			mcp.Required(),
			mcp.DefaultString("NSE"),
			mcp.Enum("NSE", "BSE", "MCX", "NFO", "BFO"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("Transaction type"),
			mcp.Required(),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity"),
			mcp.Required(),
			mcp.DefaultString("1"),
			mcp.Min(1),
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
			mcp.Description("Price (required for LIMIT order_type"),
		),
		mcp.WithString("validity",
			mcp.Description("Order Validity. (DAY for regular orders, IOC for immediate or cancel, and TTL for orders valid for specific minutes"),
			mcp.Enum("DAY", "IOC", "TTL"),
		),
		mcp.WithNumber("validity_ttl",
			mcp.Description("Order life span in minutes for TTL validity orders, required for TTL orders"),
		),
		mcp.WithNumber("disclosed_quantity",
			mcp.Description("Quantity to disclose publicly (for equity trades)"),
		),
		mcp.WithNumber("trigger_price",
			mcp.Description("The price at which an order should be triggered (SL, SL-M orders)"),
		),
		mcp.WithNumber("iceberg_legs",
			mcp.Description("Number of legs for iceberg orders"),
		),
		mcp.WithNumber("iceberg_quantity",
			mcp.Description("Quantity per leg for iceberg orders"),
		),
		mcp.WithString("tag",
			mcp.Description("An optional tag to apply to an order to identify it (alphanumeric, max 20 chars)"),
			mcp.MaxLength(20),
		),
		mcp.WithNumber("market_protection",
			mcp.Description("Market protection percentage for MARKET orders (0-100). Use -1 for auto (recommended). Required by SEBI for market orders since April 2026."),
		),
	)
}

func (*PlaceOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "place_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := SafeAssertString(args["variety"], "regular")
		orderParams := kiteconnect.OrderParams{
			Exchange:          SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:     SafeAssertString(args["tradingsymbol"], ""),
			Validity:          SafeAssertString(args["validity"], ""),
			ValidityTTL:       SafeAssertInt(args["validity_ttl"], 0),
			Product:           SafeAssertString(args["product"], ""),
			OrderType:         SafeAssertString(args["order_type"], ""),
			TransactionType:   SafeAssertString(args["transaction_type"], ""),
			Quantity:          SafeAssertInt(args["quantity"], 1),
			DisclosedQuantity: SafeAssertInt(args["disclosed_quantity"], 0),
			Price:             SafeAssertFloat64(args["price"], 0.0),
			TriggerPrice:      SafeAssertFloat64(args["trigger_price"], 0.0),
			IcebergLegs:       SafeAssertInt(args["iceberg_legs"], 0),
			IcebergQty:        SafeAssertInt(args["iceberg_quantity"], 0),
			Tag:               SafeAssertString(args["tag"], ""),
			MarketProtection:  SafeAssertFloat64(args["market_protection"], kiteconnect.MarketProtectionAuto),
		}

		// Validate order parameters
		if orderParams.OrderType == "LIMIT" && orderParams.Price <= 0 {
			return mcp.NewToolResultError("price must be greater than 0 for LIMIT orders"), nil
		}
		if (orderParams.OrderType == "SL" || orderParams.OrderType == "SL-M") && orderParams.TriggerPrice <= 0 {
			return mcp.NewToolResultError("trigger_price must be greater than 0 for SL/SL-M orders"), nil
		}
		if variety == "iceberg" && (orderParams.IcebergLegs <= 0 || orderParams.IcebergQty <= 0) {
			return mcp.NewToolResultError("iceberg_legs and iceberg_quantity must be greater than 0 for iceberg orders"), nil
		}
		if orderParams.DisclosedQuantity > 0 && orderParams.DisclosedQuantity > orderParams.Quantity {
			return mcp.NewToolResultError("disclosed_quantity cannot exceed quantity"), nil
		}

		return handler.WithSession(ctx, "place_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.PlaceOrder(variety, orderParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("place_order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "place_order")
		})
	}
}

type ModifyOrderTool struct{}

func (*ModifyOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("modify_order",
		mcp.WithDescription("Modify an existing order"),
		mcp.WithString("variety",
			mcp.Description("Order variety"),
			mcp.Required(),
			mcp.DefaultString("regular"),
			mcp.Enum("regular", "co", "amo", "iceberg", "auction"),
		),
		mcp.WithString("order_id",
			mcp.Description("Order ID"),
			mcp.Required(),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity"),
			mcp.DefaultString("1"),
			mcp.Min(1),
		),
		mcp.WithNumber("price",
			mcp.Description("Price (required for LIMIT order_type"),
		),
		mcp.WithString("order_type",
			mcp.Description("Order type"),
			mcp.Required(),
			mcp.Enum("MARKET", "LIMIT", "SL", "SL-M"),
		),
		mcp.WithNumber("trigger_price",
			mcp.Description("The price at which an order should be triggered (SL, SL-M orders)"),
		),
		mcp.WithString("validity",
			mcp.Description("Order Validity. (DAY for regular orders, IOC for immediate or cancel, and TTL for orders valid for specific minutes"),
			mcp.Enum("DAY", "IOC", "TTL"),
		),
		mcp.WithNumber("disclosed_quantity",
			mcp.Description("Quantity to disclose publicly (for equity trades)"),
		),
		mcp.WithNumber("market_protection",
			mcp.Description("Market protection percentage for MARKET orders (0-100). Use -1 for auto (recommended)."),
		),
	)
}

func (*ModifyOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "modify_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "variety", "order_id", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := SafeAssertString(args["variety"], "regular")
		orderID := SafeAssertString(args["order_id"], "")

		orderParams := kiteconnect.OrderParams{
			Quantity:          SafeAssertInt(args["quantity"], 1),
			Price:             SafeAssertFloat64(args["price"], 0.0),
			OrderType:         SafeAssertString(args["order_type"], ""),
			TriggerPrice:      SafeAssertFloat64(args["trigger_price"], 0.0),
			Validity:          SafeAssertString(args["validity"], ""),
			DisclosedQuantity: SafeAssertInt(args["disclosed_quantity"], 0),
			MarketProtection:  SafeAssertFloat64(args["market_protection"], kiteconnect.MarketProtectionAuto),
		}

		return handler.WithSession(ctx, "modify_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.ModifyOrder(variety, orderID, orderParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to modify order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "modify_order")
		})
	}
}

type CancelOrderTool struct{}

func (*CancelOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("cancel_order",
		mcp.WithDescription("Cancel an existing order"),
		mcp.WithString("variety",
			mcp.Description("Order variety"),
			mcp.Required(),
			mcp.DefaultString("regular"),
			mcp.Enum("regular", "co", "amo", "iceberg", "auction"),
		),
		mcp.WithString("order_id",
			mcp.Description("Order ID"),
			mcp.Required(),
		),
	)
}

func (*CancelOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "cancel_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "variety", "order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := SafeAssertString(args["variety"], "regular")
		orderID := SafeAssertString(args["order_id"], "")

		return handler.WithSession(ctx, "cancel_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.CancelOrder(variety, orderID, nil)
			if err != nil {
				handler.manager.Logger.Error("Failed to cancel order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to cancel order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "cancel_order")
		})
	}
}

type PlaceGTTOrderTool struct{}

func (*PlaceGTTOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("place_gtt_order",
		mcp.WithDescription("Place a GTT (Good Till Triggered) order"),
		mcp.WithString("exchange",
			mcp.Description("The exchange to which the order should be placed"),
			mcp.Required(),
			mcp.DefaultString("NSE"),
			mcp.Enum("NSE", "BSE", "MCX", "NFO", "BFO"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol"),
			mcp.Required(),
		),
		mcp.WithNumber("last_price",
			mcp.Description("Last price of the instrument"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("Transaction type"),
			mcp.Required(),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithString("product",
			mcp.Description("Product type"),
			mcp.Required(),
			mcp.Enum("CNC", "NRML", "MIS", "MTF"),
		),
		mcp.WithString("trigger_type",
			mcp.Description("GTT trigger type"),
			mcp.Required(),
			mcp.Enum("single", "two-leg"),
		),
		// For single leg trigger
		mcp.WithNumber("trigger_value",
			mcp.Description("Price point at which the GTT will be triggered (for single-leg)"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity for the order (for single-leg)"),
		),
		mcp.WithNumber("limit_price",
			mcp.Description("Limit price for the order (for single-leg)"),
		),
		// For two-leg trigger
		mcp.WithNumber("upper_trigger_value",
			mcp.Description("Upper price point at which the GTT will be triggered (for two-leg)"),
		),
		mcp.WithNumber("upper_quantity",
			mcp.Description("Quantity for the upper trigger order (for two-leg)"),
		),
		mcp.WithNumber("upper_limit_price",
			mcp.Description("Limit price for the upper trigger order (for two-leg)"),
		),
		mcp.WithNumber("lower_trigger_value",
			mcp.Description("Lower price point at which the GTT will be triggered (for two-leg)"),
		),
		mcp.WithNumber("lower_quantity",
			mcp.Description("Quantity for the lower trigger order (for two-leg)"),
		),
		mcp.WithNumber("lower_limit_price",
			mcp.Description("Limit price for the lower trigger order (for two-leg)"),
		),
	)
}

func (*PlaceGTTOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "place_gtt_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Set up basic GTT params
		gttParams := kiteconnect.GTTParams{
			Exchange:        SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			LastPrice:       SafeAssertFloat64(args["last_price"], 0.0),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
			Product:         SafeAssertString(args["product"], ""),
		}

		// Set up trigger based on trigger_type
		triggerType := SafeAssertString(args["trigger_type"], "")

		switch triggerType {
		case "single":
			triggerValue := SafeAssertFloat64(args["trigger_value"], 0.0)
			if triggerValue <= 0 {
				return mcp.NewToolResultError("trigger_value must be greater than 0"), nil
			}
			gttParams.Trigger = &kiteconnect.GTTSingleLegTrigger{
				TriggerParams: kiteconnect.TriggerParams{
					TriggerValue: triggerValue,
					Quantity:     SafeAssertFloat64(args["quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["limit_price"], 0.0),
				},
			}
		case "two-leg":
			upperTriggerValue := SafeAssertFloat64(args["upper_trigger_value"], 0.0)
			lowerTriggerValue := SafeAssertFloat64(args["lower_trigger_value"], 0.0)
			if upperTriggerValue <= 0 {
				return mcp.NewToolResultError("upper_trigger_value must be greater than 0"), nil
			}
			if lowerTriggerValue <= 0 {
				return mcp.NewToolResultError("lower_trigger_value must be greater than 0"), nil
			}
			gttParams.Trigger = &kiteconnect.GTTOneCancelsOtherTrigger{
				Upper: kiteconnect.TriggerParams{
					TriggerValue: upperTriggerValue,
					Quantity:     SafeAssertFloat64(args["upper_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["upper_limit_price"], 0.0),
				},
				Lower: kiteconnect.TriggerParams{
					TriggerValue: lowerTriggerValue,
					Quantity:     SafeAssertFloat64(args["lower_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["lower_limit_price"], 0.0),
				},
			}
		default:
			return mcp.NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}

		return handler.WithSession(ctx, "place_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.PlaceGTT(gttParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place GTT order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to place GTT order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "place_gtt_order")
		})
	}
}

type DeleteGTTOrderTool struct{}

func (*DeleteGTTOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("delete_gtt_order",
		mcp.WithDescription("Delete an existing GTT (Good Till Triggered) order"),
		mcp.WithNumber("trigger_id",
			mcp.Description("The ID of the GTT order to delete"),
			mcp.Required(),
		),
	)
}

func (*DeleteGTTOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "delete_gtt_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "trigger_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Get the trigger ID to delete
		triggerID := SafeAssertInt(args["trigger_id"], 0)

		return handler.WithSession(ctx, "delete_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.DeleteGTT(triggerID)
			if err != nil {
				handler.manager.Logger.Error("Failed to delete GTT order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to delete GTT order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "delete_gtt_order")
		})
	}
}

type ConvertPositionTool struct{}

func (*ConvertPositionTool) Tool() mcp.Tool {
	return mcp.NewTool("convert_position",
		mcp.WithDescription("Convert a position's product type (e.g., MIS to CNC for carrying intraday positions overnight, or CNC to MIS). This is commonly used at end of day to decide whether to carry or square off positions."),
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
			mcp.Description("Quantity to convert"),
			mcp.Required(),
			mcp.Min(1),
		),
		mcp.WithString("old_product",
			mcp.Description("Current product type"),
			mcp.Required(),
			mcp.Enum("CNC", "NRML", "MIS"),
		),
		mcp.WithString("new_product",
			mcp.Description("Target product type"),
			mcp.Required(),
			mcp.Enum("CNC", "NRML", "MIS"),
		),
		mcp.WithString("position_type",
			mcp.Description("Position type"),
			mcp.Required(),
			mcp.Enum("day", "overnight"),
		),
	)
}

func (*ConvertPositionTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "convert_position")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "transaction_type", "quantity", "old_product", "new_product", "position_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		positionParams := kiteconnect.ConvertPositionParams{
			Exchange:        SafeAssertString(args["exchange"], ""),
			TradingSymbol:   SafeAssertString(args["tradingsymbol"], ""),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
			Quantity:        SafeAssertInt(args["quantity"], 0),
			OldProduct:      SafeAssertString(args["old_product"], ""),
			NewProduct:      SafeAssertString(args["new_product"], ""),
			PositionType:    SafeAssertString(args["position_type"], ""),
		}

		return handler.WithSession(ctx, "convert_position", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			ok, err := session.Kite.Client.ConvertPosition(positionParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to convert position", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to convert position: %s", err.Error())), nil
			}

			return handler.MarshalResponse(map[string]bool{"success": ok}, "convert_position")
		})
	}
}

type ModifyGTTOrderTool struct{}

func (*ModifyGTTOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("modify_gtt_order",
		mcp.WithDescription("Modify an existing GTT (Good Till Triggered) order"),
		mcp.WithNumber("trigger_id",
			mcp.Description("The ID of the GTT order to modify"),
			mcp.Required(),
		),
		mcp.WithString("exchange",
			mcp.Description("The exchange to which the order should be placed"),
			mcp.Required(),
			mcp.DefaultString("NSE"),
			mcp.Enum("NSE", "BSE", "MCX", "NFO", "BFO"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol"),
			mcp.Required(),
		),
		mcp.WithNumber("last_price",
			mcp.Description("Last price of the instrument"),
			mcp.Required(),
		),
		mcp.WithString("transaction_type",
			mcp.Description("Transaction type"),
			mcp.Required(),
			mcp.Enum("BUY", "SELL"),
		),
		mcp.WithString("product",
			mcp.Description("Product type"),
			mcp.Required(),
			mcp.Enum("CNC", "NRML", "MIS", "MTF"),
		),
		mcp.WithString("trigger_type",
			mcp.Description("GTT trigger type"),
			mcp.Required(),
			mcp.Enum("single", "two-leg"),
		),
		// For single leg trigger
		mcp.WithNumber("trigger_value",
			mcp.Description("Price point at which the GTT will be triggered (for single-leg)"),
		),
		mcp.WithNumber("quantity",
			mcp.Description("Quantity for the order (for single-leg)"),
		),
		mcp.WithNumber("limit_price",
			mcp.Description("Limit price for the order (for single-leg)"),
		),
		// For two-leg trigger
		mcp.WithNumber("upper_trigger_value",
			mcp.Description("Upper price point at which the GTT will be triggered (for two-leg)"),
		),
		mcp.WithNumber("upper_quantity",
			mcp.Description("Quantity for the upper trigger order (for two-leg)"),
		),
		mcp.WithNumber("upper_limit_price",
			mcp.Description("Limit price for the upper trigger order (for two-leg)"),
		),
		mcp.WithNumber("lower_trigger_value",
			mcp.Description("Lower price point at which the GTT will be triggered (for two-leg)"),
		),
		mcp.WithNumber("lower_quantity",
			mcp.Description("Quantity for the lower trigger order (for two-leg)"),
		),
		mcp.WithNumber("lower_limit_price",
			mcp.Description("Limit price for the lower trigger order (for two-leg)"),
		),
	)
}

func (*ModifyGTTOrderTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "modify_gtt_order")
		args := request.GetArguments()

		// Validate required parameters
		if err := ValidateRequired(args, "trigger_id", "exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Get the trigger ID to modify
		triggerID := SafeAssertInt(args["trigger_id"], 0)

		// Set up basic GTT params
		gttParams := kiteconnect.GTTParams{
			Exchange:        SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			LastPrice:       SafeAssertFloat64(args["last_price"], 0.0),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
			Product:         SafeAssertString(args["product"], ""),
		}

		// Set up trigger based on trigger_type
		triggerType := SafeAssertString(args["trigger_type"], "")

		switch triggerType {
		case "single":
			triggerValue := SafeAssertFloat64(args["trigger_value"], 0.0)
			if triggerValue <= 0 {
				return mcp.NewToolResultError("trigger_value must be greater than 0"), nil
			}
			gttParams.Trigger = &kiteconnect.GTTSingleLegTrigger{
				TriggerParams: kiteconnect.TriggerParams{
					TriggerValue: triggerValue,
					Quantity:     SafeAssertFloat64(args["quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["limit_price"], 0.0),
				},
			}
		case "two-leg":
			upperTriggerValue := SafeAssertFloat64(args["upper_trigger_value"], 0.0)
			lowerTriggerValue := SafeAssertFloat64(args["lower_trigger_value"], 0.0)
			if upperTriggerValue <= 0 {
				return mcp.NewToolResultError("upper_trigger_value must be greater than 0"), nil
			}
			if lowerTriggerValue <= 0 {
				return mcp.NewToolResultError("lower_trigger_value must be greater than 0"), nil
			}
			gttParams.Trigger = &kiteconnect.GTTOneCancelsOtherTrigger{
				Upper: kiteconnect.TriggerParams{
					TriggerValue: upperTriggerValue,
					Quantity:     SafeAssertFloat64(args["upper_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["upper_limit_price"], 0.0),
				},
				Lower: kiteconnect.TriggerParams{
					TriggerValue: lowerTriggerValue,
					Quantity:     SafeAssertFloat64(args["lower_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["lower_limit_price"], 0.0),
				},
			}
		default:
			return mcp.NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}

		return handler.WithSession(ctx, "modify_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			resp, err := session.Kite.Client.ModifyGTT(triggerID, gttParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify GTT order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to modify GTT order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "modify_gtt_order")
		})
	}
}
