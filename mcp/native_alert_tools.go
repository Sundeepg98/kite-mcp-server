package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
)

// --- Place Native Alert ---

// PlaceNativeAlertTool creates a server-side alert at Zerodha (works even when MCP server is offline).
type PlaceNativeAlertTool struct{}

func (*PlaceNativeAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("place_native_alert",
		mcp.WithDescription(
			"Create a server-side price alert at Zerodha that monitors conditions even when this MCP server is offline. "+
				"Supports two types: 'simple' (notification only) and 'ato' (Alert Triggers Order — auto-places an order when the condition is met). "+
				"For ATO alerts, provide the basket order parameters. "+
				"The left-hand side (LHS) is the instrument to monitor; the right-hand side (RHS) is either a constant price or another instrument for cross-instrument alerts. "+
				"Unlike our custom set_alert (which requires a live ticker), native alerts are managed entirely by Zerodha's servers."),
		mcp.WithTitleAnnotation("Place Native Alert"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),

		// Required params
		mcp.WithString("name",
			mcp.Description("A human-readable name for the alert (e.g. 'INFY above 1500')"),
			mcp.Required(),
		),
		mcp.WithString("type",
			mcp.Description("Alert type: 'simple' (notification only) or 'ato' (auto-places order on trigger)"),
			mcp.Required(),
			mcp.Enum("simple", "ato"),
		),
		mcp.WithString("exchange",
			mcp.Description("Exchange of the instrument to monitor (LHS)"),
			mcp.Required(),
			mcp.Enum("NSE", "BSE", "MCX", "NFO", "BFO"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol of the instrument to monitor (LHS)"),
			mcp.Required(),
		),
		mcp.WithString("lhs_attribute",
			mcp.Description("The price attribute to monitor on the LHS instrument"),
			mcp.Required(),
			mcp.DefaultString("last_price"),
			mcp.Enum("last_price", "open", "high", "low", "close", "volume", "oi"),
		),
		mcp.WithString("operator",
			mcp.Description("Comparison operator: <=, >=, <, >, =="),
			mcp.Required(),
			mcp.Enum("<=", ">=", "<", ">", "=="),
		),
		mcp.WithString("rhs_type",
			mcp.Description("Right-hand side type: 'constant' for a fixed value, 'instrument' to compare against another instrument"),
			mcp.Required(),
			mcp.DefaultString("constant"),
			mcp.Enum("constant", "instrument"),
		),

		// RHS constant (when rhs_type=constant)
		mcp.WithNumber("rhs_constant",
			mcp.Description("The constant value to compare against (required when rhs_type='constant')"),
		),

		// RHS instrument (when rhs_type=instrument)
		mcp.WithString("rhs_exchange",
			mcp.Description("Exchange of the RHS instrument (required when rhs_type='instrument')"),
		),
		mcp.WithString("rhs_tradingsymbol",
			mcp.Description("Trading symbol of the RHS instrument (required when rhs_type='instrument')"),
		),
		mcp.WithString("rhs_attribute",
			mcp.Description("Price attribute of the RHS instrument (required when rhs_type='instrument')"),
			mcp.Enum("last_price", "open", "high", "low", "close", "volume", "oi"),
		),

		// ATO basket params (when type=ato)
		mcp.WithString("basket_json",
			mcp.Description(
				"JSON string describing the order basket for ATO alerts. Required when type='ato'. "+
					"Example: {\"name\":\"My basket\",\"type\":\"order\",\"tags\":[\"mcp\"],\"items\":[{\"type\":\"order\",\"tradingsymbol\":\"INFY\",\"exchange\":\"NSE\",\"weight\":1,\"params\":{\"transaction_type\":\"BUY\",\"product\":\"CNC\",\"order_type\":\"LIMIT\",\"validity\":\"DAY\",\"quantity\":1,\"price\":1500}}]}"),
		),
	)
}

func (*PlaceNativeAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "place_native_alert")
		args := request.GetArguments()

		if err := ValidateRequired(args, "name", "type", "exchange", "tradingsymbol", "lhs_attribute", "operator", "rhs_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		alertType := kiteconnect.AlertType(p.String("type", "simple"))
		rhsType := p.String("rhs_type", "constant")

		// Validate RHS params
		if rhsType == "constant" {
			if err := ValidateRequired(args, "rhs_constant"); err != nil {
				return mcp.NewToolResultError("rhs_constant is required when rhs_type='constant'"), nil
			}
		} else if rhsType == "instrument" {
			if err := ValidateRequired(args, "rhs_exchange", "rhs_tradingsymbol", "rhs_attribute"); err != nil {
				return mcp.NewToolResultError("rhs_exchange, rhs_tradingsymbol, and rhs_attribute are required when rhs_type='instrument'"), nil
			}
		}

		params := kiteconnect.AlertParams{
			Name:             p.String("name", ""),
			Type:             alertType,
			LHSExchange:      p.String("exchange", ""),
			LHSTradingSymbol: p.String("tradingsymbol", ""),
			LHSAttribute:     p.String("lhs_attribute", "last_price"),
			Operator:         kiteconnect.AlertOperator(p.String("operator", ">=")),
			RHSType:          rhsType,
			RHSConstant:      p.Float("rhs_constant", 0),
			RHSExchange:      p.String("rhs_exchange", ""),
			RHSTradingSymbol: p.String("rhs_tradingsymbol", ""),
			RHSAttribute:     p.String("rhs_attribute", ""),
		}

		// Parse basket JSON for ATO alerts
		if alertType == kiteconnect.AlertTypeATO {
			basketJSON := p.String("basket_json", "")
			if basketJSON == "" {
				return mcp.NewToolResultError("basket_json is required when type='ato'"), nil
			}
			var basket kiteconnect.Basket
			if err := json.Unmarshal([]byte(basketJSON), &basket); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Invalid basket_json: %s", err)), nil
			}
			if len(basket.Items) == 0 {
				return mcp.NewToolResultError("basket must contain at least one item"), nil
			}
			params.Basket = &basket
		}

		// Request user confirmation for ATO alerts (they place real orders)
		if alertType == kiteconnect.AlertTypeATO {
			if srv := manager.MCPServer(); srv != nil {
				msg := fmt.Sprintf("Confirm: Create ATO alert '%s' — %s:%s %s %s → auto-order on trigger",
					params.Name, params.LHSExchange, params.LHSTradingSymbol,
					string(params.Operator), formatRHS(params))
				if err := requestConfirmation(ctx, srv, msg); err != nil {
					handler.trackToolError(ctx, "place_native_alert", "user_declined")
					return mcp.NewToolResultError(err.Error()), nil
				}
			}
		}

		return handler.WithSession(ctx, "place_native_alert", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			alert, err := session.Kite.Client.CreateAlert(params)
			if err != nil {
				handler.manager.Logger.Error("Failed to create native alert", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to create native alert: %s", err)), nil
			}

			return handler.MarshalResponse(alert, "place_native_alert")
		})
	}
}

// --- List Native Alerts ---

// ListNativeAlertsTool lists all server-side alerts at Zerodha.
type ListNativeAlertsTool struct{}

func (*ListNativeAlertsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_native_alerts",
		mcp.WithDescription(
			"List all server-side (native) alerts from Zerodha. These are alerts managed by Zerodha's servers, "+
				"unlike custom alerts (list_alerts) which are managed by this MCP server. "+
				"Optionally filter by status (enabled/disabled/deleted)."),
		mcp.WithTitleAnnotation("List Native Alerts"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("status",
			mcp.Description("Filter by alert status"),
			mcp.Enum("enabled", "disabled", "deleted"),
		),
	)
}

func (*ListNativeAlertsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "list_native_alerts")

		return handler.WithSession(ctx, "list_native_alerts", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			p := NewArgParser(args)
			filters := make(map[string]string)
			if status := p.String("status", ""); status != "" {
				filters["status"] = status
			}

			alerts, err := session.Kite.Client.GetAlerts(filters)
			if err != nil {
				handler.manager.Logger.Error("Failed to list native alerts", "error", err)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to list native alerts: %s", err)), nil
			}

			if len(alerts) == 0 {
				return mcp.NewToolResultText("No native alerts found. Use place_native_alert to create one."), nil
			}

			return handler.MarshalResponse(map[string]interface{}{
				"alerts": alerts,
				"count":  len(alerts),
			}, "list_native_alerts")
		})
	}
}

// --- Modify Native Alert ---

// ModifyNativeAlertTool modifies an existing server-side alert at Zerodha.
type ModifyNativeAlertTool struct{}

func (*ModifyNativeAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("modify_native_alert",
		mcp.WithDescription(
			"Modify an existing server-side alert at Zerodha by UUID. "+
				"All fields must be provided (the API replaces the entire alert definition). "+
				"Use list_native_alerts to find the UUID of the alert to modify."),
		mcp.WithTitleAnnotation("Modify Native Alert"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),

		// UUID of the alert to modify
		mcp.WithString("uuid",
			mcp.Description("UUID of the alert to modify (from list_native_alerts)"),
			mcp.Required(),
		),

		// Same params as create
		mcp.WithString("name",
			mcp.Description("Updated name for the alert"),
			mcp.Required(),
		),
		mcp.WithString("type",
			mcp.Description("Alert type: 'simple' or 'ato'"),
			mcp.Required(),
			mcp.Enum("simple", "ato"),
		),
		mcp.WithString("exchange",
			mcp.Description("Exchange of the instrument to monitor (LHS)"),
			mcp.Required(),
			mcp.Enum("NSE", "BSE", "MCX", "NFO", "BFO"),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Trading symbol of the instrument to monitor (LHS)"),
			mcp.Required(),
		),
		mcp.WithString("lhs_attribute",
			mcp.Description("The price attribute to monitor on the LHS instrument"),
			mcp.Required(),
			mcp.DefaultString("last_price"),
			mcp.Enum("last_price", "open", "high", "low", "close", "volume", "oi"),
		),
		mcp.WithString("operator",
			mcp.Description("Comparison operator"),
			mcp.Required(),
			mcp.Enum("<=", ">=", "<", ">", "=="),
		),
		mcp.WithString("rhs_type",
			mcp.Description("Right-hand side type"),
			mcp.Required(),
			mcp.Enum("constant", "instrument"),
		),
		mcp.WithNumber("rhs_constant",
			mcp.Description("Constant value to compare against (when rhs_type='constant')"),
		),
		mcp.WithString("rhs_exchange",
			mcp.Description("Exchange of the RHS instrument (when rhs_type='instrument')"),
		),
		mcp.WithString("rhs_tradingsymbol",
			mcp.Description("Trading symbol of the RHS instrument (when rhs_type='instrument')"),
		),
		mcp.WithString("rhs_attribute",
			mcp.Description("Price attribute of the RHS instrument (when rhs_type='instrument')"),
			mcp.Enum("last_price", "open", "high", "low", "close", "volume", "oi"),
		),
		mcp.WithString("basket_json",
			mcp.Description("JSON string describing the order basket for ATO alerts (required when type='ato')"),
		),
	)
}

func (*ModifyNativeAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "modify_native_alert")
		args := request.GetArguments()

		if err := ValidateRequired(args, "uuid", "name", "type", "exchange", "tradingsymbol", "lhs_attribute", "operator", "rhs_type"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		uuid := p.String("uuid", "")
		alertType := kiteconnect.AlertType(p.String("type", "simple"))
		rhsType := p.String("rhs_type", "constant")

		if rhsType == "constant" {
			if err := ValidateRequired(args, "rhs_constant"); err != nil {
				return mcp.NewToolResultError("rhs_constant is required when rhs_type='constant'"), nil
			}
		} else if rhsType == "instrument" {
			if err := ValidateRequired(args, "rhs_exchange", "rhs_tradingsymbol", "rhs_attribute"); err != nil {
				return mcp.NewToolResultError("rhs_exchange, rhs_tradingsymbol, and rhs_attribute are required when rhs_type='instrument'"), nil
			}
		}

		params := kiteconnect.AlertParams{
			Name:             p.String("name", ""),
			Type:             alertType,
			LHSExchange:      p.String("exchange", ""),
			LHSTradingSymbol: p.String("tradingsymbol", ""),
			LHSAttribute:     p.String("lhs_attribute", "last_price"),
			Operator:         kiteconnect.AlertOperator(p.String("operator", ">=")),
			RHSType:          rhsType,
			RHSConstant:      p.Float("rhs_constant", 0),
			RHSExchange:      p.String("rhs_exchange", ""),
			RHSTradingSymbol: p.String("rhs_tradingsymbol", ""),
			RHSAttribute:     p.String("rhs_attribute", ""),
		}

		if alertType == kiteconnect.AlertTypeATO {
			basketJSON := p.String("basket_json", "")
			if basketJSON == "" {
				return mcp.NewToolResultError("basket_json is required when type='ato'"), nil
			}
			var basket kiteconnect.Basket
			if err := json.Unmarshal([]byte(basketJSON), &basket); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Invalid basket_json: %s", err)), nil
			}
			if len(basket.Items) == 0 {
				return mcp.NewToolResultError("basket must contain at least one item"), nil
			}
			params.Basket = &basket
		}

		// Confirm ATO modifications
		if alertType == kiteconnect.AlertTypeATO {
			if srv := manager.MCPServer(); srv != nil {
				msg := fmt.Sprintf("Confirm: Modify ATO alert %s → %s:%s %s %s",
					uuid, params.LHSExchange, params.LHSTradingSymbol,
					string(params.Operator), formatRHS(params))
				if err := requestConfirmation(ctx, srv, msg); err != nil {
					handler.trackToolError(ctx, "modify_native_alert", "user_declined")
					return mcp.NewToolResultError(err.Error()), nil
				}
			}
		}

		return handler.WithSession(ctx, "modify_native_alert", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			alert, err := session.Kite.Client.ModifyAlert(uuid, params)
			if err != nil {
				handler.manager.Logger.Error("Failed to modify native alert", "error", err, "uuid", uuid)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to modify native alert: %s", err)), nil
			}

			return handler.MarshalResponse(alert, "modify_native_alert")
		})
	}
}

// --- Delete Native Alert ---

// DeleteNativeAlertTool deletes one or more server-side alerts at Zerodha.
type DeleteNativeAlertTool struct{}

func (*DeleteNativeAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("delete_native_alert",
		mcp.WithDescription(
			"Delete one or more server-side (native) alerts at Zerodha by UUID. "+
				"Use list_native_alerts to find the UUID(s) of alerts to delete."),
		mcp.WithTitleAnnotation("Delete Native Alert"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("uuid",
			mcp.Description("UUID of the alert to delete (from list_native_alerts). For multiple alerts, pass comma-separated UUIDs."),
			mcp.Required(),
		),
	)
}

func (*DeleteNativeAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "delete_native_alert")
		args := request.GetArguments()

		if err := ValidateRequired(args, "uuid"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		uuidStr := NewArgParser(args).String("uuid", "")
		if uuidStr == "" {
			return mcp.NewToolResultError("uuid is required"), nil
		}

		// Support comma-separated UUIDs for batch delete
		uuids := splitAndTrim(uuidStr)
		if len(uuids) == 0 {
			return mcp.NewToolResultError("at least one valid UUID is required"), nil
		}

		return handler.WithSession(ctx, "delete_native_alert", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			err := session.Kite.Client.DeleteAlerts(uuids...)
			if err != nil {
				handler.manager.Logger.Error("Failed to delete native alert(s)", "error", err, "uuids", uuids)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to delete native alert(s): %s", err)), nil
			}

			if len(uuids) == 1 {
				return mcp.NewToolResultText(fmt.Sprintf("Native alert %s deleted.", uuids[0])), nil
			}
			return mcp.NewToolResultText(fmt.Sprintf("%d native alerts deleted.", len(uuids))), nil
		})
	}
}

// --- Get Native Alert History ---

// GetNativeAlertHistoryTool retrieves the trigger history of a specific native alert.
type GetNativeAlertHistoryTool struct{}

func (*GetNativeAlertHistoryTool) Tool() mcp.Tool {
	return mcp.NewTool("get_native_alert_history",
		mcp.WithDescription(
			"Get the trigger history of a specific server-side alert at Zerodha. "+
				"Shows when the alert was triggered, the price at that moment, and order execution details for ATO alerts."),
		mcp.WithTitleAnnotation("Native Alert History"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("uuid",
			mcp.Description("UUID of the alert (from list_native_alerts)"),
			mcp.Required(),
		),
	)
}

func (*GetNativeAlertHistoryTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_native_alert_history")
		args := request.GetArguments()

		if err := ValidateRequired(args, "uuid"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		uuid := NewArgParser(args).String("uuid", "")

		return handler.WithSession(ctx, "get_native_alert_history", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			history, err := session.Kite.Client.GetAlertHistory(uuid)
			if err != nil {
				handler.manager.Logger.Error("Failed to get native alert history", "error", err, "uuid", uuid)
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get alert history: %s", err)), nil
			}

			if len(history) == 0 {
				return mcp.NewToolResultText(fmt.Sprintf("No trigger history for alert %s.", uuid)), nil
			}

			return handler.MarshalResponse(map[string]interface{}{
				"uuid":    uuid,
				"history": history,
				"count":   len(history),
			}, "get_native_alert_history")
		})
	}
}

// --- Helpers ---

// formatRHS returns a human-readable string for the right-hand side of an alert condition.
func formatRHS(params kiteconnect.AlertParams) string {
	if params.RHSType == "constant" {
		return fmt.Sprintf("%.2f", params.RHSConstant)
	}
	return fmt.Sprintf("%s:%s (%s)", params.RHSExchange, params.RHSTradingSymbol, params.RHSAttribute)
}

// splitAndTrim splits a comma-separated string and trims whitespace from each part,
// discarding empty entries.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
