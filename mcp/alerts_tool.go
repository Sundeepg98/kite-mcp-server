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

type AlertsTool struct{}

func (*AlertsTool) Tool() mcp.Tool {
	return mcp.NewTool("alerts",
		mcp.WithDescription("Manage Kite price alerts - create, modify, delete, and retrieve alerts with optional history"),
		mcp.WithString("mode",
			mcp.Description("Operation mode: get=create=retrieve alerts, create=new alert, modify=update alert, delete=remove alerts"),
			mcp.Required(),
			mcp.Enum("get", "create", "modify", "delete"),
		),
		mcp.WithArray("uuids",
			mcp.Description("Array of alert UUIDs (for get/modify/delete modes). Single UUID for specific alert, multiple for batch operations"),
			mcp.Required(),
			mcp.Items(map[string]any{
				"type": "string",
			}),
		),
		mcp.WithString("status",
			mcp.Description("Filter alerts by status (only for get mode)"),
			mcp.Enum("enabled", "disabled", "deleted"),
		),
		mcp.WithString("type",
			mcp.Description("Filter alerts by type (only for get mode)"),
			mcp.Enum("simple", "ato"),
		),
		mcp.WithBoolean("history",
			mcp.Description("Include alert history (only for get mode, default: false)"),
		),
		mcp.WithString("name",
			mcp.Description("Alert name (required for create/modify modes)"),
		),
		mcp.WithString("alert_type",
			mcp.Description("Alert type: simple or ato (required for create/modify modes)"),
			mcp.Enum("simple", "ato"),
		),
		mcp.WithString("lhs_exchange",
			mcp.Description("Exchange for left-hand side instrument (required for create/modify modes)"),
		),
		mcp.WithString("lhs_tradingsymbol",
			mcp.Description("Trading symbol for left-hand side instrument (required for create/modify modes)"),
		),
		mcp.WithString("lhs_attribute",
			mcp.Description("Attribute for left-hand side (e.g., LastTradedPrice) (required for create/modify modes)"),
		),
		mcp.WithString("operator",
			mcp.Description("Comparison operator: <=, >=, <, >, == (required for create/modify modes)"),
			mcp.Enum("<=", ">=", "<", ">", "=="),
		),
		mcp.WithString("rhs_type",
			mcp.Description("Right-hand side type: constant or instrument (required for create/modify modes)"),
			mcp.Enum("constant", "instrument"),
		),
		mcp.WithNumber("rhs_constant",
			mcp.Description("Constant value for right-hand side (required if rhs_type=constant)"),
		),
		mcp.WithString("rhs_exchange",
			mcp.Description("Exchange for right-hand side instrument (required if rhs_type=instrument)"),
		),
		mcp.WithString("rhs_tradingsymbol",
			mcp.Description("Trading symbol for right-hand side instrument (required if rhs_type=instrument)"),
		),
		mcp.WithString("rhs_attribute",
			mcp.Description("Attribute for right-hand side (required if rhs_type=instrument)"),
		),
		mcp.WithString("basket",
			mcp.Description("JSON string containing basket configuration for ATO alerts (optional, only for alert_type=ato)"),
		),
	)
}

func (*AlertsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.GetArguments()
		mode := SafeAssertString(args["mode"], "")

		switch mode {
		case "get":
			return handler.WithKiteClient(ctx, "alerts_get", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
				return handleGetAlerts(handler, args, client)
			})
		case "create":
			return handler.WithKiteClient(ctx, "alerts_create", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
				return handleCreateAlert(handler, args, client)
			})
		case "modify":
			return handler.WithKiteClient(ctx, "alerts_modify", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
				return handleModifyAlert(handler, args, client)
			})
		case "delete":
			return handler.WithKiteClient(ctx, "alerts_delete", func(client *kiteconnect.Client) (*mcp.CallToolResult, error) {
				return handleDeleteAlerts(handler, args, client)
			})
		default:
			return mcp.NewToolResultError("Invalid mode. Must be one of: get, create, modify, delete"), nil
		}
	}
}

func handleGetAlerts(handler *ToolHandler, args map[string]interface{}, client *kiteconnect.Client) (*mcp.CallToolResult, error) {
	uuids := SafeAssertStringArray(args["uuids"])
	includeHistory := SafeAssertBool(args["history"], false)
	status := SafeAssertString(args["status"], "")
	alertType := SafeAssertString(args["type"], "")

	// Build filters
	filters := make(map[string]string)
	if status != "" {
		filters["status"] = status
	}
	if alertType != "" {
		filters["type"] = alertType
	}

	// Handle single UUID
	if len(uuids) == 1 {
		uuid := uuids[0]
		alert, err := client.GetAlert(uuid)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get alert %s: %v", uuid, err)), nil
		}

		response := map[string]interface{}{
			"alert": alert,
		}

		if includeHistory {
			history, err := client.GetAlertHistory(uuid)
			if err != nil {
				handler.manager.Logger.Warn("Failed to get alert history", "uuid", uuid, "error", err)
			} else {
				response["history"] = history
			}
		}

		return handler.MarshalResponse(response, "alerts_get")
	}

	// Handle multiple UUIDs or no UUIDs
	var alerts []kiteconnect.Alert
	var err error

	if len(uuids) > 0 {
		// Get all alerts and filter by UUIDs
		allAlerts, err := client.GetAlerts(nil)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get alerts: %v", err)), nil
		}

		// Filter by provided UUIDs
		uuidSet := make(map[string]bool)
		for _, uuid := range uuids {
			uuidSet[uuid] = true
		}

		for _, alert := range allAlerts {
			if uuidSet[alert.UUID] {
				alerts = append(alerts, alert)
			}
		}
	} else {
		// Get all alerts with filters
		alerts, err = client.GetAlerts(filters)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get alerts: %v", err)), nil
		}
	}

	response := map[string]interface{}{
		"alerts": alerts,
	}

	// Add history if requested
	if includeHistory && len(alerts) > 0 {
		histories := make(map[string]interface{})
		for _, alert := range alerts {
			history, err := client.GetAlertHistory(alert.UUID)
			if err != nil {
				handler.manager.Logger.Warn("Failed to get alert history", "uuid", alert.UUID, "error", err)
			} else {
				histories[alert.UUID] = history
			}
		}
		response["histories"] = histories
	}

	return handler.MarshalResponse(response, "alerts_get")
}

func handleCreateAlert(handler *ToolHandler, args map[string]interface{}, client *kiteconnect.Client) (*mcp.CallToolResult, error) {
	if err := validateAlertParams(args, true); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	alertParams, err := buildAlertParams(args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to build alert parameters: %v", err)), nil
	}

	alert, err := client.CreateAlert(alertParams)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create alert: %v", err)), nil
	}

	return handler.MarshalResponse(map[string]interface{}{
		"alert": alert,
	}, "alerts_create")
}

func handleModifyAlert(handler *ToolHandler, args map[string]interface{}, client *kiteconnect.Client) (*mcp.CallToolResult, error) {
	uuids := SafeAssertStringArray(args["uuids"])
	if len(uuids) == 0 {
		return mcp.NewToolResultError("UUID is required for modify mode"), nil
	}

	if err := validateAlertParams(args, false); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	alertParams, err := buildAlertParams(args)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to build alert parameters: %v", err)), nil
	}

	alert, err := client.ModifyAlert(uuids[0], alertParams)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to modify alert %s: %v", uuids[0], err)), nil
	}

	return handler.MarshalResponse(map[string]interface{}{
		"alert": alert,
	}, "alerts_modify")
}

func handleDeleteAlerts(handler *ToolHandler, args map[string]interface{}, client *kiteconnect.Client) (*mcp.CallToolResult, error) {
	uuids := SafeAssertStringArray(args["uuids"])
	if len(uuids) == 0 {
		return mcp.NewToolResultError("At least one UUID is required for delete mode"), nil
	}

	err := client.DeleteAlerts(uuids...)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to delete alerts: %v", err)), nil
	}

	return handler.MarshalResponse(map[string]interface{}{
		"success":       true,
		"deleted_uuids": uuids,
		"deleted_count": len(uuids),
	}, "alerts_delete")
}

func validateAlertParams(args map[string]interface{}, isCreate bool) error {
	// Validate required parameters
	requiredParams := []string{"name", "alert_type", "lhs_exchange", "lhs_tradingsymbol", "lhs_attribute", "operator", "rhs_type"}
	for _, param := range requiredParams {
		if SafeAssertString(args[param], "") == "" {
			return ValidationError{Parameter: param, Message: "is required"}
		}
	}

	// Validate RHS parameters based on type
	rhsType := SafeAssertString(args["rhs_type"], "")
	switch rhsType {
	case "constant":
		if _, ok := args["rhs_constant"]; !ok {
			return ValidationError{Parameter: "rhs_constant", Message: "is required when rhs_type=constant"}
		}
	case "instrument":
		requiredInstrumentParams := []string{"rhs_exchange", "rhs_tradingsymbol", "rhs_attribute"}
		for _, param := range requiredInstrumentParams {
			if SafeAssertString(args[param], "") == "" {
				return ValidationError{Parameter: param, Message: "is required when rhs_type=instrument"}
			}
		}
	default:
		return ValidationError{Parameter: "rhs_type", Message: "must be 'constant' or 'instrument'"}
	}

	// Validate basket for ATO alerts
	alertType := SafeAssertString(args["alert_type"], "")
	if alertType == "ato" {
		if basketStr, ok := args["basket"]; ok && SafeAssertString(basketStr, "") != "" {
			// Validate that basket is valid JSON
			var basket kiteconnect.Basket
			if err := json.Unmarshal([]byte(SafeAssertString(basketStr, "")), &basket); err != nil {
				return ValidationError{Parameter: "basket", Message: "must be valid JSON"}
			}
		}
	}

	return nil
}

func buildAlertParams(args map[string]interface{}) (kiteconnect.AlertParams, error) {
	params := kiteconnect.AlertParams{
		Name:             SafeAssertString(args["name"], ""),
		Type:             kiteconnect.AlertType(SafeAssertString(args["alert_type"], "")),
		LHSExchange:      SafeAssertString(args["lhs_exchange"], ""),
		LHSTradingSymbol: SafeAssertString(args["lhs_tradingsymbol"], ""),
		LHSAttribute:     SafeAssertString(args["lhs_attribute"], ""),
		Operator:         kiteconnect.AlertOperator(SafeAssertString(args["operator"], "")),
		RHSType:          SafeAssertString(args["rhs_type"], ""),
		RHSConstant:      SafeAssertFloat64(args["rhs_constant"], 0),
		RHSExchange:      SafeAssertString(args["rhs_exchange"], ""),
		RHSTradingSymbol: SafeAssertString(args["rhs_tradingsymbol"], ""),
		RHSAttribute:     SafeAssertString(args["rhs_attribute"], ""),
	}

	// Parse basket if provided
	if basketStr, ok := args["basket"]; ok && SafeAssertString(basketStr, "") != "" {
		var basket kiteconnect.Basket
		if err := json.Unmarshal([]byte(SafeAssertString(basketStr, "")), &basket); err != nil {
			return params, fmt.Errorf("failed to parse basket JSON: %v", err)
		}
		params.Basket = &basket
	}

	return params, nil
}
