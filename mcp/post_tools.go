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
		mcp.WithString("client_order_id",
			mcp.Description("Optional idempotency key (Alpaca-style). Supply a unique opaque string for each logical order intent; the server rejects duplicate submissions of the same key within 15 minutes. Use to make retries safe after network timeouts. Leave blank if not needed."),
			mcp.MaxLength(64),
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
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		return handler.WithSession(ctx, "place_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Dispatch through the CommandBus so PlaceOrderUseCase runs under
			// the shared pipeline. The session-pinned broker.Client rides on
			// ctx so the handler-side resolver reuses it without a second
			// credential lookup.
			cmdCtx := kc.WithBroker(ctx, session.Broker)
			qty, _ := domain.NewQuantity(orderParams.Quantity)
			raw, err := handler.CommandBus().DispatchWithResult(cmdCtx, cqrs.PlaceOrderCommand{
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
				// Elicitation at line ~156 has already gated this dispatch,
				// so the downstream riskguard re-check can be told the user
				// has acknowledged the order.
				Confirmed: true,
			})
			if err != nil {
				handler.Logger().Error("Failed to place order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("place_order: %s", err.Error())), nil
			}
			orderID, _ := raw.(string)

			// Brief delay then check fill status for immediate feedback.
			// Order history dispatch also rides the bus (QueryBus side).
			if orderID != "" {
				time.Sleep(1500 * time.Millisecond)
				histRaw, histErr := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetOrderHistoryQuery{
					Email:   session.Email,
					OrderID: orderID,
				})
				if histErr == nil {
					history, _ := histRaw.([]broker.Order)
					if len(history) > 0 {
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
		mcp.WithString("client_order_id",
			mcp.Description("Optional idempotency key (Alpaca-style). Supply a unique opaque string for each logical modify intent; the server rejects duplicate submissions of the same key within 15 minutes. Use to make retries safe after network timeouts. Leave blank if not needed."),
			mcp.MaxLength(64),
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
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("modify_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "modify_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}

		return handler.WithSession(ctx, "modify_order", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			cmdCtx := kc.WithBroker(ctx, session.Broker)
			raw, err := handler.CommandBus().DispatchWithResult(cmdCtx, cqrs.ModifyOrderCommand{
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
				// Elicitation already gated this dispatch — see note in
				// the PlaceOrderCommand dispatch site above.
				Confirmed: true,
			})
			if err != nil {
				handler.Logger().Error("Failed to modify order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("modify_order: %s", err.Error())), nil
			}
			resp, terr := BusResult[broker.OrderResponse](raw)
			if terr != nil {
				handler.Logger().Error("modify_order bus result type mismatch", "error", terr)
				return mcp.NewToolResultError(terr.Error()), nil
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
			cmdCtx := kc.WithBroker(ctx, session.Broker)
			raw, err := handler.CommandBus().DispatchWithResult(cmdCtx, cqrs.CancelOrderCommand{
				Email:   session.Email,
				OrderID: orderID,
				Variety: variety,
			})
			if err != nil {
				handler.Logger().Error("Failed to cancel order", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("cancel_order: %s", err.Error())), nil
			}
			resp, terr := BusResult[broker.OrderResponse](raw)
			if terr != nil {
				handler.Logger().Error("cancel_order bus result type mismatch", "error", terr)
				return mcp.NewToolResultError(terr.Error()), nil
			}
			return handler.MarshalResponse(resp, "cancel_order")
		})
	}
}

// GTT tools (PlaceGTTOrderTool, DeleteGTTOrderTool, ModifyGTTOrderTool)
// moved to mcp/gtt_tools.go — same package, same wire format, just a
// cohesion-based file split.

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
			// convert_position goes through SessionSvc on the handler side,
			// so we don't attach a session-pinned broker to ctx. Pre-migration
			// behavior is preserved exactly.
			raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.ConvertPositionCommand{
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
			ok, _ := raw.(bool)
			return handler.MarshalResponse(map[string]bool{"success": ok}, "convert_position")
		})
	}
}

// ModifyGTTOrderTool moved to mcp/gtt_tools.go alongside the other
// GTT-specific handlers.

func init() {
	RegisterInternalTool(&CancelOrderTool{})
	RegisterInternalTool(&ConvertPositionTool{})
	RegisterInternalTool(&ModifyOrderTool{})
	RegisterInternalTool(&PlaceOrderTool{})
}
