package mcp

import (
	"context"
	"fmt"
	"math"
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
		mcp.WithDestructiveHintAnnotation(true),
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

		chatIDFloat := SafeAssertFloat64(args["chat_id"], 0)
		if math.IsNaN(chatIDFloat) || math.IsInf(chatIDFloat, 0) || chatIDFloat > float64(math.MaxInt64) || chatIDFloat < float64(math.MinInt64) {
			return mcp.NewToolResultError("Invalid chat_id: must be a valid integer"), nil
		}
		chatID := int64(chatIDFloat)
		if chatID == 0 {
			return mcp.NewToolResultError("Invalid chat ID"), nil
		}

		manager.AlertStore().SetTelegramChatID(email, chatID)
		manager.Logger.Debug("Telegram chat ID registered", "email", email, "chat_id", chatID)

		return mcp.NewToolResultText(fmt.Sprintf("Telegram notifications configured for %s. You'll receive alerts at chat ID %d.", email, chatID)), nil
	}
}

// SetAlertTool creates a price alert for an instrument.
type SetAlertTool struct{}

func (*SetAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("set_alert",
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithDescription("Set a price alert for an instrument. Supports absolute price alerts (above/below) and percentage-change alerts (drop_pct/rise_pct). "+
			"For percentage alerts, 'price' is the percentage threshold (e.g. 5.0 for 5%) and 'reference_price' is the baseline price to measure against. "+
			"If reference_price is omitted for percentage alerts, the current LTP is used. "+
			"Requires the ticker to be running with the instrument subscribed."),
		mcp.WithString("instrument",
			mcp.Description("Instrument in exchange:tradingsymbol format (e.g. 'NSE:INFY')"),
			mcp.Required(),
		),
		mcp.WithNumber("price",
			mcp.Description("For above/below: the target price. For drop_pct/rise_pct: the percentage threshold (e.g. 5.0 for 5%)"),
			mcp.Required(),
		),
		mcp.WithString("direction",
			mcp.Description("Alert direction: 'above' (price >= target), 'below' (price <= target), 'drop_pct' (price drops X% from reference), 'rise_pct' (price rises X% from reference)"),
			mcp.Required(),
			mcp.Enum("above", "below", "drop_pct", "rise_pct"),
		),
		mcp.WithNumber("reference_price",
			mcp.Description("Baseline price for percentage alerts (drop_pct/rise_pct). If omitted, the current LTP is fetched automatically. Ignored for above/below alerts."),
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
		referencePrice := SafeAssertFloat64(args["reference_price"], 0)

		if targetPrice <= 0 {
			return mcp.NewToolResultError("Price must be positive"), nil
		}

		direction := alerts.Direction(directionStr)
		if !alerts.ValidDirections[direction] {
			return mcp.NewToolResultError("Direction must be 'above', 'below', 'drop_pct', or 'rise_pct'"), nil
		}

		// For percentage alerts, validate the threshold is reasonable
		if alerts.IsPercentageDirection(direction) && targetPrice > 100 {
			return mcp.NewToolResultError("Percentage threshold cannot exceed 100%"), nil
		}

		// Resolve instrument to get token, exchange, and tradingsymbol
		inst, err := manager.Instruments.GetByID(instrumentID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Instrument not found: %s", instrumentID)), nil
		}

		// Parse exchange and tradingsymbol from the instrument ID
		parts := strings.SplitN(instrumentID, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid instrument ID format: %s (expected exchange:symbol)", instrumentID)
		}
		exchange := parts[0]
		tradingsymbol := inst.Tradingsymbol

		// For percentage alerts, fetch current LTP as reference if not provided
		if alerts.IsPercentageDirection(direction) && referencePrice <= 0 {
			sess := server.ClientSessionFromContext(ctx)
			sessionID := sess.SessionID()
			kiteSession, _, clientErr := manager.GetOrCreateSessionWithEmail(sessionID, email)
			if clientErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get Kite session for LTP lookup: %s", clientErr)), nil
			}
			ltpResp, ltpErr := kiteSession.Kite.Client.GetLTP(instrumentID)
			if ltpErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch current LTP for reference price: %s", ltpErr)), nil
			}
			ltpData, ok := ltpResp[instrumentID]
			if !ok || ltpData.LastPrice <= 0 {
				return mcp.NewToolResultError(fmt.Sprintf("No LTP available for %s — provide reference_price manually", instrumentID)), nil
			}
			referencePrice = ltpData.LastPrice
		}

		alertID, err := manager.AlertStore().AddWithReferencePrice(email, tradingsymbol, exchange, inst.InstrumentToken, targetPrice, direction, referencePrice)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to set alert: %s", err)), nil
		}

		var result string
		if alerts.IsPercentageDirection(direction) {
			result = fmt.Sprintf("Alert set: %s %s %.2f%% from reference %.2f (ID: %s)", instrumentID, directionStr, targetPrice, referencePrice, alertID)
		} else {
			result = fmt.Sprintf("Alert set: %s %s %.2f (ID: %s)", instrumentID, directionStr, targetPrice, alertID)
		}

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
		mcp.WithReadOnlyHintAnnotation(true),
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
		mcp.WithDestructiveHintAnnotation(true),
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
