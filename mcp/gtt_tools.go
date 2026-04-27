package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// GTT (Good Till Triggered) order tools. Split out from post_tools.go
// as part of the monolith cleanup — GTT orders have a distinct risk
// profile (deferred execution, no daily expiry) and warrant their own
// file for future GTT-specific middleware decisions.

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
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
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
			// Wave D Slice D7: GTT use cases are startup-constructed
			// with m.sessionSvc; per-request kc.WithBroker dropped.
			raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.PlaceGTTCommand{
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
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to place GTT order: %s", err.Error())), nil
			}
			resp, terr := BusResult[broker.GTTResponse](raw)
			if terr != nil {
				handler.LoggerPort().Error(ctx, "place_gtt_order bus result type mismatch", terr)
				return mcp.NewToolResultError(terr.Error()), nil
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
			// Wave D Slice D7: GTT use cases are startup-constructed
			// with m.sessionSvc; per-request kc.WithBroker dropped.
			raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.DeleteGTTCommand{
				Email:     session.Email,
				TriggerID: triggerID,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to delete GTT order: %s", err.Error())), nil
			}
			resp, terr := BusResult[broker.GTTResponse](raw)
			if terr != nil {
				handler.LoggerPort().Error(ctx, "delete_gtt_order bus result type mismatch", terr)
				return mcp.NewToolResultError(terr.Error()), nil
			}
			return handler.MarshalResponse(resp, "delete_gtt_order")
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
		if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
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
			// Wave D Slice D7: GTT use cases are startup-constructed
			// with m.sessionSvc; per-request kc.WithBroker dropped.
			raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.ModifyGTTCommand{
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
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to modify GTT order: %s", err.Error())), nil
			}
			resp, terr := BusResult[broker.GTTResponse](raw)
			if terr != nil {
				handler.LoggerPort().Error(ctx, "modify_gtt_order bus result type mismatch", terr)
				return mcp.NewToolResultError(terr.Error()), nil
			}
			return handler.MarshalResponse(resp, "modify_gtt_order")
		})
	}
}

func init() {
	RegisterInternalTool(&DeleteGTTOrderTool{})
	RegisterInternalTool(&ModifyGTTOrderTool{})
	RegisterInternalTool(&PlaceGTTOrderTool{})
}
