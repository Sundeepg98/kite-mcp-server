package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// nativeAlertAdapter bridges broker.NativeAlertCapable to usecases.NativeAlertClient.
type nativeAlertAdapter struct {
	nac broker.NativeAlertCapable
}

func (a *nativeAlertAdapter) CreateAlert(params any) (any, error) {
	p := params.(broker.NativeAlertParams)
	return a.nac.CreateNativeAlert(p)
}

func (a *nativeAlertAdapter) ModifyAlert(uuid string, params any) (any, error) {
	p := params.(broker.NativeAlertParams)
	return a.nac.ModifyNativeAlert(uuid, p)
}

func (a *nativeAlertAdapter) DeleteAlerts(uuids ...string) error {
	return a.nac.DeleteNativeAlerts(uuids...)
}

func (a *nativeAlertAdapter) GetAlerts(filters map[string]string) (any, error) {
	return a.nac.GetNativeAlerts(filters)
}

func (a *nativeAlertAdapter) GetAlertHistory(uuid string) (any, error) {
	return a.nac.GetNativeAlertHistory(uuid)
}

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
		alertType := p.String("type", "simple")
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

		params := broker.NativeAlertParams{
			Name:             p.String("name", ""),
			Type:             alertType,
			LHSExchange:      p.String("exchange", ""),
			LHSTradingSymbol: p.String("tradingsymbol", ""),
			LHSAttribute:     p.String("lhs_attribute", "last_price"),
			Operator:         p.String("operator", ">="),
			RHSType:          rhsType,
			RHSConstant:      p.Float("rhs_constant", 0),
			RHSExchange:      p.String("rhs_exchange", ""),
			RHSTradingSymbol: p.String("rhs_tradingsymbol", ""),
			RHSAttribute:     p.String("rhs_attribute", ""),
		}

		// Validate and attach basket JSON for ATO alerts
		if alertType == "ato" {
			basketJSON := p.String("basket_json", "")
			if basketJSON == "" {
				return mcp.NewToolResultError("basket_json is required when type='ato'"), nil
			}
			params.BasketJSON = basketJSON
		}

		// Request user confirmation for ATO alerts (they place real orders)
		if alertType == "ato" {
			if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
				msg := fmt.Sprintf("Confirm: Create ATO alert '%s' — %s:%s %s %s → auto-order on trigger",
					params.Name, params.LHSExchange, params.LHSTradingSymbol,
					params.Operator, formatNativeAlertRHS(params))
				if err := requestConfirmation(ctx, srv, msg); err != nil {
					handler.trackToolError(ctx, "place_native_alert", "user_declined")
					return mcp.NewToolResultError(err.Error()), nil
				}
			}
		}

		return handler.WithSession(ctx, "place_native_alert", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			if _, ok := session.Broker.(broker.NativeAlertCapable); !ok {
				return mcp.NewToolResultError("Native alerts are not supported by the current broker"), nil
			}

			email := oauth.EmailFromContext(ctx)
			alert, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.PlaceNativeAlertCommand{
				Email:  email,
				Params: params,
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
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
			nac, ok := session.Broker.(broker.NativeAlertCapable)
			if !ok {
				return mcp.NewToolResultError("Native alerts are not supported by the current broker"), nil
			}

			args := request.GetArguments()
			p := NewArgParser(args)
			filters := make(map[string]string)
			if status := p.String("status", ""); status != "" {
				filters["status"] = status
			}

			email := oauth.EmailFromContext(ctx)
			adapter := &nativeAlertAdapter{nac: nac}
			dispatchCtx := cqrs.WithNativeAlertClient(ctx, usecases.NativeAlertClient(adapter))
			alertsRaw, err := handler.QueryBus().DispatchWithResult(dispatchCtx, cqrs.ListNativeAlertsQuery{Email: email, Filters: filters})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Check if empty
			alerts, ok := alertsRaw.([]broker.NativeAlert)
			if ok && len(alerts) == 0 {
				return mcp.NewToolResultText("No native alerts found. Use place_native_alert to create one."), nil
			}

			return handler.MarshalResponse(map[string]any{
				"alerts": alertsRaw,
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
		alertType := p.String("type", "simple")
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

		params := broker.NativeAlertParams{
			Name:             p.String("name", ""),
			Type:             alertType,
			LHSExchange:      p.String("exchange", ""),
			LHSTradingSymbol: p.String("tradingsymbol", ""),
			LHSAttribute:     p.String("lhs_attribute", "last_price"),
			Operator:         p.String("operator", ">="),
			RHSType:          rhsType,
			RHSConstant:      p.Float("rhs_constant", 0),
			RHSExchange:      p.String("rhs_exchange", ""),
			RHSTradingSymbol: p.String("rhs_tradingsymbol", ""),
			RHSAttribute:     p.String("rhs_attribute", ""),
		}

		if alertType == "ato" {
			basketJSON := p.String("basket_json", "")
			if basketJSON == "" {
				return mcp.NewToolResultError("basket_json is required when type='ato'"), nil
			}
			params.BasketJSON = basketJSON
		}

		// Confirm ATO modifications
		if alertType == "ato" {
			if srv := handler.deps.MCPServer.MCPServer(); srv != nil {
				msg := fmt.Sprintf("Confirm: Modify ATO alert %s → %s:%s %s %s",
					uuid, params.LHSExchange, params.LHSTradingSymbol,
					params.Operator, formatNativeAlertRHS(params))
				if err := requestConfirmation(ctx, srv, msg); err != nil {
					handler.trackToolError(ctx, "modify_native_alert", "user_declined")
					return mcp.NewToolResultError(err.Error()), nil
				}
			}
		}

		return handler.WithSession(ctx, "modify_native_alert", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			if _, ok := session.Broker.(broker.NativeAlertCapable); !ok {
				return mcp.NewToolResultError("Native alerts are not supported by the current broker"), nil
			}

			email := oauth.EmailFromContext(ctx)
			alert, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.ModifyNativeAlertCommand{
				Email:  email,
				UUID:   uuid,
				Params: params,
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
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
			if _, ok := session.Broker.(broker.NativeAlertCapable); !ok {
				return mcp.NewToolResultError("Native alerts are not supported by the current broker"), nil
			}

			email := oauth.EmailFromContext(ctx)
			if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.DeleteNativeAlertCommand{
				Email: email,
				UUIDs: uuids,
			}); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
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
			nac, ok := session.Broker.(broker.NativeAlertCapable)
			if !ok {
				return mcp.NewToolResultError("Native alerts are not supported by the current broker"), nil
			}

			email := oauth.EmailFromContext(ctx)
			adapter := &nativeAlertAdapter{nac: nac}
			dispatchCtx := cqrs.WithNativeAlertClient(ctx, usecases.NativeAlertClient(adapter))
			historyRaw, err := handler.QueryBus().DispatchWithResult(dispatchCtx, cqrs.GetNativeAlertHistoryQuery{Email: email, UUID: uuid})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}

			history, ok := historyRaw.([]broker.NativeAlertHistoryEntry)
			if ok && len(history) == 0 {
				return mcp.NewToolResultText(fmt.Sprintf("No trigger history for alert %s.", uuid)), nil
			}

			return handler.MarshalResponse(map[string]any{
				"uuid":    uuid,
				"history": historyRaw,
			}, "get_native_alert_history")
		})
	}
}

// --- Helpers ---

// formatNativeAlertRHS returns a human-readable string for the right-hand side of an alert condition.
func formatNativeAlertRHS(params broker.NativeAlertParams) string {
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

func init() {
	RegisterInternalTool(&DeleteNativeAlertTool{})
	RegisterInternalTool(&GetNativeAlertHistoryTool{})
	RegisterInternalTool(&ListNativeAlertsTool{})
	RegisterInternalTool(&ModifyNativeAlertTool{})
	RegisterInternalTool(&PlaceNativeAlertTool{})
}
