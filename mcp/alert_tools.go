package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// SetupTelegramTool registers the user's Telegram chat ID for alert notifications.
type SetupTelegramTool struct{}

func (*SetupTelegramTool) Tool() mcp.Tool {
	return mcp.NewTool("setup_telegram",
		mcp.WithDescription("Register your Telegram chat ID for price alert notifications. To get your chat ID: 1) Message @userinfobot on Telegram, 2) It will reply with your chat ID."),
		mcp.WithNumber("chat_id",
			mcp.Description("Your Telegram chat ID (get it from @userinfobot)"),
			mcp.Required(),
		),
	)
}

func (*SetupTelegramTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "setup_telegram")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "chat_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		chatID := int64(SafeAssertFloat64(args["chat_id"], 0))
		if chatID == 0 {
			return mcp.NewToolResultError("Invalid chat ID"), nil
		}

		manager.AlertStore().SetTelegramChatID(email, chatID)
		manager.Logger.Info("Telegram chat ID registered", "email", email, "chat_id", chatID)

		return mcp.NewToolResultText(fmt.Sprintf("Telegram notifications configured for %s. You'll receive alerts at chat ID %d.", email, chatID)), nil
	}
}

// SetAlertTool creates a price alert for an instrument.
type SetAlertTool struct{}

func (*SetAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("set_alert",
		mcp.WithDescription("Set a price alert for an instrument. When the price crosses the target in the specified direction, you'll be notified via Telegram (if configured). Requires the ticker to be running with the instrument subscribed."),
		mcp.WithString("instrument",
			mcp.Description("Instrument in exchange:tradingsymbol format (e.g. 'NSE:INFY')"),
			mcp.Required(),
		),
		mcp.WithNumber("price",
			mcp.Description("Target price to trigger the alert"),
			mcp.Required(),
		),
		mcp.WithString("direction",
			mcp.Description("Trigger when price goes 'above' or 'below' the target"),
			mcp.Required(),
			mcp.Enum("above", "below"),
		),
	)
}

func (*SetAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "set_alert")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "instrument", "price", "direction"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instrumentID := SafeAssertString(args["instrument"], "")
		targetPrice := SafeAssertFloat64(args["price"], 0)
		directionStr := SafeAssertString(args["direction"], "above")

		if targetPrice <= 0 {
			return mcp.NewToolResultError("Price must be positive"), nil
		}

		direction := alerts.Direction(directionStr)
		if direction != alerts.DirectionAbove && direction != alerts.DirectionBelow {
			return mcp.NewToolResultError("Direction must be 'above' or 'below'"), nil
		}

		// Resolve instrument to get token, exchange, and tradingsymbol
		inst, err := manager.Instruments.GetByID(instrumentID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Instrument not found: %s", instrumentID)), nil
		}

		// Parse exchange and tradingsymbol from the instrument ID
		parts := strings.SplitN(instrumentID, ":", 2)
		exchange := parts[0]
		tradingsymbol := inst.Tradingsymbol

		alertID := manager.AlertStore().Add(email, tradingsymbol, exchange, inst.InstrumentToken, targetPrice, direction)

		result := fmt.Sprintf("Alert set: %s %s %.2f (ID: %s)", instrumentID, directionStr, targetPrice, alertID)

		// Check if Telegram is configured
		if _, ok := manager.AlertStore().GetTelegramChatID(email); !ok {
			result += "\n\nNote: Telegram not configured. Use setup_telegram to receive notifications."
		}

		// Check if ticker is running
		if !manager.TickerService().IsRunning(email) {
			result += "\n\nNote: Ticker not running. Use start_ticker and subscribe_instruments for real-time alerts."
		}

		return mcp.NewToolResultText(result), nil
	}
}

// ListAlertsTool lists all alerts for the current user.
type ListAlertsTool struct{}

func (*ListAlertsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_alerts",
		mcp.WithDescription("List all price alerts for the current user, including triggered and active alerts."),
	)
}

func (*ListAlertsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "list_alerts")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		alertList := manager.AlertStore().List(email)
		if len(alertList) == 0 {
			return mcp.NewToolResultText("No alerts configured. Use set_alert to create one."), nil
		}

		return handler.MarshalResponse(alertList, "list_alerts")
	}
}

// DeleteAlertTool deletes a price alert by ID.
type DeleteAlertTool struct{}

func (*DeleteAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("delete_alert",
		mcp.WithDescription("Delete a price alert by its ID."),
		mcp.WithString("alert_id",
			mcp.Description("The alert ID to delete (from list_alerts)"),
			mcp.Required(),
		),
	)
}

func (*DeleteAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "delete_alert")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "alert_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		alertID := SafeAssertString(args["alert_id"], "")
		if err := manager.AlertStore().Delete(email, alertID); err != nil {
			handler.trackToolError(ctx, "delete_alert", "delete_error")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to delete alert: %s", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Alert %s deleted.", alertID)), nil
	}
}
