package mcp

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

type PlaceOrderTool struct{}

var placeOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"variety": {
			"type": "string",
			"description": "Order variety",
			"default": "regular",
			"enum": ["regular", "co", "amo", "iceberg", "auction"]
		},
		"exchange": {
			"type": "string",
			"description": "The exchange to which the order should be placed",
			"default": "NSE",
			"enum": ["NSE", "BSE", "MCX", "NFO", "BFO"]
		},
		"tradingsymbol": {
			"type": "string",
			"description": "Trading symbol"
		},
		"transaction_type": {
			"type": "string",
			"description": "Transaction type",
			"enum": ["BUY", "SELL"]
		},
		"quantity": {
			"type": "number",
			"description": "Quantity",
			"default": 1,
			"minimum": 1
		},
		"product": {
			"type": "string",
			"description": "Product type",
			"enum": ["CNC", "NRML", "MIS", "MTF"]
		},
		"order_type": {
			"type": "string",
			"description": "Order type",
			"enum": ["MARKET", "LIMIT", "SL", "SL-M"]
		},
		"price": {
			"type": "number",
			"description": "Price (required for LIMIT order_type)"
		},
		"validity": {
			"type": "string",
			"description": "Order Validity. (DAY for regular orders, IOC for immediate or cancel, and TTL for orders valid for specific minutes)",
			"enum": ["DAY", "IOC", "TTL"]
		},
		"validity_ttl": {
			"type": "number",
			"description": "Order life span in minutes for TTL validity orders, required for TTL orders"
		},
		"disclosed_quantity": {
			"type": "number",
			"description": "Quantity to disclose publicly (for equity trades)"
		},
		"trigger_price": {
			"type": "number",
			"description": "The price at which an order should be triggered (SL, SL-M orders)"
		},
		"iceberg_legs": {
			"type": "number",
			"description": "Number of legs for iceberg orders"
		},
		"iceberg_quantity": {
			"type": "number",
			"description": "Quantity per leg for iceberg orders"
		},
		"tag": {
			"type": "string",
			"description": "An optional tag to apply to an order to identify it (alphanumeric, max 20 chars)",
			"maxLength": 20
		},
		"market_protection": {
			"type": "number",
			"description": "Market protection percentage for MARKET and SL-M orders. Values: 0 (no protection), 0-100 (custom %), -1 (auto protection)"
		}
	},
	"required": ["variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"]
}`)

func (*PlaceOrderTool) Definition() *mcp.Tool {
	return NewTool("place_order", "Place an order", placeOrderSchema)
}

func (*PlaceOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "variety", "exchange", "tradingsymbol", "transaction_type", "quantity", "product", "order_type"); err != nil {
			return NewToolResultError(err.Error()), nil
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
			MarketProtection:  SafeAssertFloat64(args["market_protection"], 0.0),
		}
		return handler.WithKiteClient(request, "place_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.PlaceOrder(variety, orderParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place order", "error", err)
				return NewToolResultError("Failed to place order"), nil
			}
			return handler.MarshalResponse(resp, "place_order")
		})
	}
}

type ModifyOrderTool struct{}

var modifyOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"variety": {
			"type": "string",
			"description": "Order variety",
			"default": "regular",
			"enum": ["regular", "co", "amo", "iceberg", "auction"]
		},
		"order_id": {
			"type": "string",
			"description": "Order ID"
		},
		"quantity": {
			"type": "number",
			"description": "Quantity",
			"default": 1,
			"minimum": 1
		},
		"price": {
			"type": "number",
			"description": "Price (required for LIMIT order_type)"
		},
		"order_type": {
			"type": "string",
			"description": "Order type",
			"enum": ["MARKET", "LIMIT", "SL", "SL-M"]
		},
		"trigger_price": {
			"type": "number",
			"description": "The price at which an order should be triggered (SL, SL-M orders)"
		},
		"validity": {
			"type": "string",
			"description": "Order Validity. (DAY for regular orders, IOC for immediate or cancel, and TTL for orders valid for specific minutes)",
			"enum": ["DAY", "IOC", "TTL"]
		},
		"disclosed_quantity": {
			"type": "number",
			"description": "Quantity to disclose publicly (for equity trades)"
		}
	},
	"required": ["variety", "order_id", "order_type"]
}`)

func (*ModifyOrderTool) Definition() *mcp.Tool {
	return NewTool("modify_order", "Modify an existing order", modifyOrderSchema)
}

func (*ModifyOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "variety", "order_id", "order_type"); err != nil {
			return NewToolResultError(err.Error()), nil
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
		}
		return handler.WithKiteClient(request, "modify_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.ModifyOrder(variety, orderID, orderParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify order", "error", err)
				return NewToolResultError("Failed to modify order"), nil
			}
			return handler.MarshalResponse(resp, "modify_order")
		})
	}
}

type CancelOrderTool struct{}

var cancelOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"variety": {
			"type": "string",
			"description": "Order variety",
			"default": "regular",
			"enum": ["regular", "co", "amo", "iceberg", "auction"]
		},
		"order_id": {
			"type": "string",
			"description": "Order ID"
		}
	},
	"required": ["variety", "order_id"]
}`)

func (*CancelOrderTool) Definition() *mcp.Tool {
	return NewTool("cancel_order", "Cancel an existing order", cancelOrderSchema)
}

func (*CancelOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "variety", "order_id"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		variety := SafeAssertString(args["variety"], "regular")
		orderID := SafeAssertString(args["order_id"], "")
		return handler.WithKiteClient(request, "cancel_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.CancelOrder(variety, orderID, nil)
			if err != nil {
				handler.manager.Logger.Error("Failed to cancel order", "error", err)
				return NewToolResultError("Failed to cancel order"), nil
			}
			return handler.MarshalResponse(resp, "cancel_order")
		})
	}
}

type PlaceGTTOrderTool struct{}

var placeGTTOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"exchange": {
			"type": "string",
			"description": "The exchange to which the order should be placed",
			"default": "NSE",
			"enum": ["NSE", "BSE", "MCX", "NFO", "BFO"]
		},
		"tradingsymbol": {
			"type": "string",
			"description": "Trading symbol"
		},
		"last_price": {
			"type": "number",
			"description": "Last price of the instrument"
		},
		"transaction_type": {
			"type": "string",
			"description": "Transaction type",
			"enum": ["BUY", "SELL"]
		},
		"product": {
			"type": "string",
			"description": "Product type",
			"enum": ["CNC", "NRML", "MIS", "MTF"]
		},
		"trigger_type": {
			"type": "string",
			"description": "GTT trigger type",
			"enum": ["single", "two-leg"]
		},
		"trigger_value": {
			"type": "number",
			"description": "Price point at which the GTT will be triggered (for single-leg)"
		},
		"quantity": {
			"type": "number",
			"description": "Quantity for the order (for single-leg)"
		},
		"limit_price": {
			"type": "number",
			"description": "Limit price for the order (for single-leg)"
		},
		"upper_trigger_value": {
			"type": "number",
			"description": "Upper price point at which the GTT will be triggered (for two-leg)"
		},
		"upper_quantity": {
			"type": "number",
			"description": "Quantity for the upper trigger order (for two-leg)"
		},
		"upper_limit_price": {
			"type": "number",
			"description": "Limit price for the upper trigger order (for two-leg)"
		},
		"lower_trigger_value": {
			"type": "number",
			"description": "Lower price point at which the GTT will be triggered (for two-leg)"
		},
		"lower_quantity": {
			"type": "number",
			"description": "Quantity for the lower trigger order (for two-leg)"
		},
		"lower_limit_price": {
			"type": "number",
			"description": "Limit price for the lower trigger order (for two-leg)"
		}
	},
	"required": ["exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"]
}`)

func (*PlaceGTTOrderTool) Definition() *mcp.Tool {
	return NewTool("place_gtt_order", "Place a GTT (Good Till Triggered) order", placeGTTOrderSchema)
}

func (*PlaceGTTOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "exchange", "tradingsymbol", "last_price", "transaction_type", "product", "trigger_type"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		gttParams := kiteconnect.GTTParams{
			Exchange:        SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			LastPrice:       SafeAssertFloat64(args["last_price"], 0.0),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
			Product:         SafeAssertString(args["product"], ""),
		}
		triggerType := SafeAssertString(args["trigger_type"], "")
		switch triggerType {
		case "single":
			gttParams.Trigger = &kiteconnect.GTTSingleLegTrigger{
				TriggerParams: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["limit_price"], 0.0),
				},
			}
		case "two-leg":
			gttParams.Trigger = &kiteconnect.GTTOneCancelsOtherTrigger{
				Upper: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["upper_trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["upper_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["upper_limit_price"], 0.0),
				},
				Lower: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["lower_trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["lower_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["lower_limit_price"], 0.0),
				},
			}
		default:
			return NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}

		return handler.WithKiteClient(request, "place_gtt_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.PlaceGTT(gttParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to place GTT order", "error", err)
				return NewToolResultError("Failed to place GTT order"), nil
			}
			return handler.MarshalResponse(resp, "place_gtt_order")
		})
	}
}

type DeleteGTTOrderTool struct{}

var deleteGTTOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"trigger_id": {
			"type": "number",
			"description": "The ID of the GTT order to delete"
		}
	},
	"required": ["trigger_id"]
}`)

func (*DeleteGTTOrderTool) Definition() *mcp.Tool {
	return NewTool("delete_gtt_order", "Delete an existing GTT (Good Till Triggered) order", deleteGTTOrderSchema)
}

func (*DeleteGTTOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "trigger_id"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		triggerID := SafeAssertInt(args["trigger_id"], 0)
		return handler.WithKiteClient(request, "delete_gtt_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.DeleteGTT(triggerID)
			if err != nil {
				handler.manager.Logger.Error("Failed to delete GTT order", "error", err)
				return NewToolResultError("Failed to delete GTT order"), nil
			}
			return handler.MarshalResponse(resp, "delete_gtt_order")
		})
	}
}

type ModifyGTTOrderTool struct{}

var modifyGTTOrderSchema = json.RawMessage(`{
	"type": "object",
	"properties": {
		"trigger_id": {
			"type": "number",
			"description": "The ID of the GTT order to modify"
		},
		"exchange": {
			"type": "string",
			"description": "The exchange to which the order should be placed",
			"default": "NSE",
			"enum": ["NSE", "BSE", "MCX", "NFO", "BFO"]
		},
		"tradingsymbol": {
			"type": "string",
			"description": "Trading symbol"
		},
		"last_price": {
			"type": "number",
			"description": "Last price of the instrument"
		},
		"transaction_type": {
			"type": "string",
			"description": "Transaction type",
			"enum": ["BUY", "SELL"]
		},
		"trigger_type": {
			"type": "string",
			"description": "GTT trigger type",
			"enum": ["single", "two-leg"]
		},
		"trigger_value": {
			"type": "number",
			"description": "Price point at which the GTT will be triggered (for single-leg)"
		},
		"quantity": {
			"type": "number",
			"description": "Quantity for the order (for single-leg)"
		},
		"limit_price": {
			"type": "number",
			"description": "Limit price for the order (for single-leg)"
		},
		"upper_trigger_value": {
			"type": "number",
			"description": "Upper price point at which the GTT will be triggered (for two-leg)"
		},
		"upper_quantity": {
			"type": "number",
			"description": "Quantity for the upper trigger order (for two-leg)"
		},
		"upper_limit_price": {
			"type": "number",
			"description": "Limit price for the upper trigger order (for two-leg)"
		},
		"lower_trigger_value": {
			"type": "number",
			"description": "Lower price point at which the GTT will be triggered (for two-leg)"
		},
		"lower_quantity": {
			"type": "number",
			"description": "Quantity for the lower trigger order (for two-leg)"
		},
		"lower_limit_price": {
			"type": "number",
			"description": "Limit price for the lower trigger order (for two-leg)"
		}
	},
	"required": ["trigger_id", "exchange", "tradingsymbol", "last_price", "transaction_type", "trigger_type"]
}`)

func (*ModifyGTTOrderTool) Definition() *mcp.Tool {
	return NewTool("modify_gtt_order", "Modify an existing GTT (Good Till Triggered) order", modifyGTTOrderSchema)
}

func (*ModifyGTTOrderTool) Handler(manager *kc.Manager) ToolHandler {
	handler := NewToolHandler(manager)
	return func(request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := GetArguments(request)
		if err := ValidateRequired(args, "trigger_id", "exchange", "tradingsymbol", "last_price", "transaction_type", "trigger_type"); err != nil {
			return NewToolResultError(err.Error()), nil
		}
		triggerID := SafeAssertInt(args["trigger_id"], 0)
		gttParams := kiteconnect.GTTParams{
			Exchange:        SafeAssertString(args["exchange"], "NSE"),
			Tradingsymbol:   SafeAssertString(args["tradingsymbol"], ""),
			LastPrice:       SafeAssertFloat64(args["last_price"], 0.0),
			TransactionType: SafeAssertString(args["transaction_type"], ""),
		}
		triggerType := SafeAssertString(args["trigger_type"], "")
		switch triggerType {
		case "single":
			gttParams.Trigger = &kiteconnect.GTTSingleLegTrigger{
				TriggerParams: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["limit_price"], 0.0),
				},
			}
		case "two-leg":
			gttParams.Trigger = &kiteconnect.GTTOneCancelsOtherTrigger{
				Upper: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["upper_trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["upper_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["upper_limit_price"], 0.0),
				},
				Lower: kiteconnect.TriggerParams{
					TriggerValue: SafeAssertFloat64(args["lower_trigger_value"], 0.0),
					Quantity:     SafeAssertFloat64(args["lower_quantity"], 0.0),
					LimitPrice:   SafeAssertFloat64(args["lower_limit_price"], 0.0),
				},
			}
		default:
			return NewToolResultError("Invalid trigger_type. Must be 'single' or 'two-leg'"), nil
		}
		return handler.WithKiteClient(request, "modify_gtt_order", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
			resp, err := client.ModifyGTT(triggerID, gttParams)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify GTT order", "error", err)
				return NewToolResultError("Failed to modify GTT order"), nil
			}
			return handler.MarshalResponse(resp, "modify_gtt_order")
		})
	}
}
