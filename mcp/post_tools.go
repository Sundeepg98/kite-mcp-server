package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// sessionBrokerResolver wraps an already-resolved broker.Client so that
// usecases.BrokerResolver can be satisfied without a second credential lookup.
// This is the per-request adapter created inside WithSession callbacks.
type sessionBrokerResolver struct {
	client broker.Client
}

func (r *sessionBrokerResolver) GetBrokerForEmail(_ string) (broker.Client, error) {
	return r.client, nil
}

type PlaceOrderTool struct{}

func (*PlaceOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("place_order",
		mcp.WithDescription("Place an order"),
		mcp.WithTitleAnnotation("Place Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := p.String("variety", "regular")
		orderParams := broker.OrderParams{
			Exchange:         p.String("exchange", "NSE"),
			Tradingsymbol:    p.String("tradingsymbol", ""),
			Validity:         p.String("validity", ""),
			Product:          p.String("product", ""),
			OrderType:        p.String("order_type", ""),
			TransactionType:  p.String("transaction_type", ""),
			Quantity:         p.Int("quantity", 1),
			DisclosedQty:     p.Int("disclosed_quantity", 0),
			Price:            p.Float("price", 0.0),
			TriggerPrice:     p.Float("trigger_price", 0.0),
			Tag:              p.String("tag", "mcp"),
			MarketProtection: p.Float("market_protection", broker.MarketProtectionAuto),
			Variety:          variety,
		}

		// Iceberg params — validated here, passed through via Variety (adapter handles Kite-specific fields)
		icebergLegs := p.Int("iceberg_legs", 0)
		icebergQty := p.Int("iceberg_quantity", 0)

		// Validate order parameters
		if orderParams.OrderType == "LIMIT" && orderParams.Price <= 0 {
			return mcp.NewToolResultError("price must be greater than 0 for LIMIT orders"), nil
		}
		if (orderParams.OrderType == "SL" || orderParams.OrderType == "SL-M") && orderParams.TriggerPrice <= 0 {
			return mcp.NewToolResultError("trigger_price must be greater than 0 for SL/SL-M orders"), nil
		}
		if variety == "iceberg" && (icebergLegs <= 0 || icebergQty <= 0) {
			return mcp.NewToolResultError("iceberg_legs and iceberg_quantity must be greater than 0 for iceberg orders"), nil
		}
		if orderParams.DisclosedQty > 0 && orderParams.DisclosedQty > orderParams.Quantity {
			return mcp.NewToolResultError("disclosed_quantity cannot exceed quantity"), nil
		}

		// Request user confirmation via elicitation before placing the order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		return handler.WithSession(ctx, "place_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Route through PlaceOrderUseCase (riskguard + broker + event dispatch).
			uc := usecases.NewPlaceOrderUseCase(
				&sessionBrokerResolver{client: session.Broker},
				handler.manager.RiskGuard(),
				handler.manager.EventDispatcher(),
				handler.manager.Logger,
			)
			qty, _ := domain.NewQuantity(orderParams.Quantity)
			cmd := cqrs.PlaceOrderCommand{
				Email:           session.Email,
				Instrument:      domain.NewInstrumentKey(orderParams.Exchange, orderParams.Tradingsymbol),
				TransactionType: orderParams.TransactionType,
				Qty:             qty,
				Price:           domain.NewINR(orderParams.Price),
				OrderType:       orderParams.OrderType,
				Product:         orderParams.Product,
				TriggerPrice:    orderParams.TriggerPrice,
				Validity:        orderParams.Validity,
				Variety:         orderParams.Variety,
				Tag:             orderParams.Tag,
			}
			orderID, err := uc.Execute(ctx, cmd)
			if err != nil {
				handler.manager.Logger.Error("Failed to place order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("place_order: %s", err.Error())), nil
			}

			// Brief delay then check fill status for immediate feedback
			if orderID != "" {
				time.Sleep(1500 * time.Millisecond)
				historyUC := usecases.NewGetOrderHistoryUseCase(
					&sessionBrokerResolver{client: session.Broker},
					manager.Logger,
				)
				history, histErr := historyUC.Execute(ctx, cqrs.GetOrderHistoryQuery{
					Email:   session.Email,
					OrderID: orderID,
				})
				if histErr == nil && len(history) > 0 {
					latest := history[len(history)-1]
					enriched := map[string]any{
						"order_id":         orderID,
						"status":           latest.Status,
						"filled_quantity":  latest.FilledQuantity,
						"average_price":    latest.AveragePrice,
						"pending_quantity": latest.Quantity - latest.FilledQuantity,
						"status_message":   latest.StatusMessage,
					}
					return handler.MarshalResponse(enriched, "place_order")
				}
			}

			return handler.MarshalResponse(map[string]any{"order_id": orderID}, "place_order")
		})
	}
}

type ModifyOrderTool struct{}

func (*ModifyOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("modify_order",
		mcp.WithDescription("Modify an existing order"),
		mcp.WithTitleAnnotation("Modify Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("variety", "order_id", "order_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := p.String("variety", "regular")
		orderID := p.String("order_id", "")

		orderParams := broker.OrderParams{
			Quantity:         p.Int("quantity", 1),
			Price:            p.Float("price", 0.0),
			OrderType:        p.String("order_type", ""),
			TriggerPrice:     p.Float("trigger_price", 0.0),
			Validity:         p.String("validity", ""),
			DisclosedQty:     p.Int("disclosed_quantity", 0),
			MarketProtection: p.Float("market_protection", broker.MarketProtectionAuto),
			Variety:          variety,
		}

		// Request user confirmation via elicitation before modifying the order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("modify_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "modify_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		return handler.WithSession(ctx, "modify_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Route through ModifyOrderUseCase (riskguard + broker + event dispatch).
			uc := usecases.NewModifyOrderUseCase(
				&sessionBrokerResolver{client: session.Broker},
				handler.manager.RiskGuard(),
				handler.manager.EventDispatcher(),
				handler.manager.Logger,
			)
			cmd := cqrs.ModifyOrderCommand{
				Email:            session.Email,
				OrderID:          orderID,
				Variety:          variety,
				Quantity:         orderParams.Quantity,
				Price:            domain.NewINR(orderParams.Price),
				TriggerPrice:     orderParams.TriggerPrice,
				OrderType:        orderParams.OrderType,
				Validity:         orderParams.Validity,
				DisclosedQty:     orderParams.DisclosedQty,
				MarketProtection: orderParams.MarketProtection,
			}
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("modify_order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "modify_order")
		})
	}
}

type CancelOrderTool struct{}

func (*CancelOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("cancel_order",
		mcp.WithDescription("Cancel an existing order"),
		mcp.WithTitleAnnotation("Cancel Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("variety", "order_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		variety := p.String("variety", "regular")
		orderID := p.String("order_id", "")

		return handler.WithSession(ctx, "cancel_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Route through CancelOrderUseCase (broker + event dispatch).
			uc := usecases.NewCancelOrderUseCase(
				&sessionBrokerResolver{client: session.Broker},
				handler.manager.EventDispatcher(),
				handler.manager.Logger,
			)
			cmd := cqrs.CancelOrderCommand{
				Email:   session.Email,
				OrderID: orderID,
				Variety: variety,
			}
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
				handler.manager.Logger.Error("Failed to cancel order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("cancel_order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "cancel_order")
		})
	}
}

type PlaceGTTOrderTool struct{}

func (*PlaceGTTOrderTool) Tool() mcp.Tool {
	return mcp.NewTool("place_gtt_order",
		mcp.WithDescription("Place a GTT (Good Till Triggered) order"),
		mcp.WithTitleAnnotation("Place GTT Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Request user confirmation via elicitation before placing the GTT.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_gtt_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_gtt_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		triggerType := p.String("trigger_type", "")

		// Validate trigger-type-specific fields before session lookup.
		switch triggerType {
		case "single":
			triggerValue := p.Float("trigger_value", 0.0)
			if triggerValue <= 0 {
				return mcp.NewToolResultError("trigger_value must be greater than 0"), nil
			}
		case "two-leg":
			if p.Float("upper_trigger_value", 0.0) <= 0 {
				return mcp.NewToolResultError("upper_trigger_value must be greater than 0"), nil
			}
			if p.Float("lower_trigger_value", 0.0) <= 0 {
				return mcp.NewToolResultError("lower_trigger_value must be greater than 0"), nil
			}
		default:
			return mcp.NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}

		return handler.WithSession(ctx, "place_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			cmd := cqrs.PlaceGTTCommand{
				Email:             session.Email,
				Instrument:        domain.NewInstrumentKey(p.String("exchange", "NSE"), p.String("tradingsymbol", "")),
				LastPrice:         domain.NewINR(p.Float("last_price", 0.0)),
				TransactionType:   p.String("transaction_type", ""),
				Product:           p.String("product", ""),
				Type:              triggerType,
				TriggerValue:      p.Float("trigger_value", 0.0),
				Quantity:          p.Float("quantity", 0.0),
				LimitPrice:        domain.NewINR(p.Float("limit_price", 0.0)),
				UpperTriggerValue: p.Float("upper_trigger_value", 0.0),
				UpperQuantity:     p.Float("upper_quantity", 0.0),
				UpperLimitPrice:   domain.NewINR(p.Float("upper_limit_price", 0.0)),
				LowerTriggerValue: p.Float("lower_trigger_value", 0.0),
				LowerQuantity:     p.Float("lower_quantity", 0.0),
				LowerLimitPrice:   domain.NewINR(p.Float("lower_limit_price", 0.0)),
			}

			uc := usecases.NewPlaceGTTUseCase(&sessionBrokerResolver{client: session.Broker}, manager.Logger)
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
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
		mcp.WithTitleAnnotation("Delete GTT Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("trigger_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Get the trigger ID to delete
		triggerID := p.Int("trigger_id", 0)

		return handler.WithSession(ctx, "delete_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			cmd := cqrs.DeleteGTTCommand{
				Email:     session.Email,
				TriggerID: triggerID,
			}

			uc := usecases.NewDeleteGTTUseCase(&sessionBrokerResolver{client: session.Broker}, manager.Logger)
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
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
		mcp.WithTitleAnnotation("Convert Position"),
		mcp.WithDestructiveHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("exchange", "tradingsymbol", "transaction_type", "quantity", "old_product", "new_product", "position_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return handler.WithSession(ctx, "convert_position", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			uc := usecases.NewConvertPositionUseCase(manager.SessionSvc(), manager.Logger)
			ok, err := uc.Execute(ctx, cqrs.ConvertPositionCommand{
				Email:           session.Email,
				Exchange:        p.String("exchange", ""),
				Tradingsymbol:   p.String("tradingsymbol", ""),
				TransactionType: p.String("transaction_type", ""),
				Quantity:        p.Int("quantity", 0),
				OldProduct:      p.String("old_product", ""),
				NewProduct:      p.String("new_product", ""),
				PositionType:    p.String("position_type", ""),
			})
			if err != nil {
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
		mcp.WithTitleAnnotation("Modify GTT Order"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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
		p := NewArgParser(args)

		// Validate required parameters
		if err := p.Required("trigger_id", "exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		// Request user confirmation via elicitation before modifying the GTT.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("modify_gtt_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "modify_gtt_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		triggerType := p.String("trigger_type", "")

		// Validate trigger-type-specific fields before session lookup.
		switch triggerType {
		case "single":
			if p.Float("trigger_value", 0.0) <= 0 {
				return mcp.NewToolResultError("trigger_value must be greater than 0"), nil
			}
		case "two-leg":
			if p.Float("upper_trigger_value", 0.0) <= 0 {
				return mcp.NewToolResultError("upper_trigger_value must be greater than 0"), nil
			}
			if p.Float("lower_trigger_value", 0.0) <= 0 {
				return mcp.NewToolResultError("lower_trigger_value must be greater than 0"), nil
			}
		default:
			return mcp.NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}

		return handler.WithSession(ctx, "modify_gtt_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			cmd := cqrs.ModifyGTTCommand{
				Email:             session.Email,
				TriggerID:         p.Int("trigger_id", 0),
				Instrument:        domain.NewInstrumentKey(p.String("exchange", "NSE"), p.String("tradingsymbol", "")),
				LastPrice:         domain.NewINR(p.Float("last_price", 0.0)),
				TransactionType:   p.String("transaction_type", ""),
				Product:           p.String("product", ""),
				Type:              triggerType,
				TriggerValue:      p.Float("trigger_value", 0.0),
				Quantity:          p.Float("quantity", 0.0),
				LimitPrice:        domain.NewINR(p.Float("limit_price", 0.0)),
				UpperTriggerValue: p.Float("upper_trigger_value", 0.0),
				UpperQuantity:     p.Float("upper_quantity", 0.0),
				UpperLimitPrice:   domain.NewINR(p.Float("upper_limit_price", 0.0)),
				LowerTriggerValue: p.Float("lower_trigger_value", 0.0),
				LowerQuantity:     p.Float("lower_quantity", 0.0),
				LowerLimitPrice:   domain.NewINR(p.Float("lower_limit_price", 0.0)),
			}

			uc := usecases.NewModifyGTTUseCase(&sessionBrokerResolver{client: session.Broker}, manager.Logger)
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to modify GTT order: %s", err.Error())), nil
			}

			return handler.MarshalResponse(resp, "modify_gtt_order")
		})
	}
}
