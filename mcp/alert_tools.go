package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// instrumentResolverAdapter adapts instruments.Manager to satisfy usecases.InstrumentResolver.
type instrumentResolverAdapter struct {
	mgr *instruments.Manager
}

func (a *instrumentResolverAdapter) GetInstrumentToken(exchange, tradingsymbol string) (uint32, error) {
	inst, err := a.mgr.GetByTradingsymbol(exchange, tradingsymbol)
	if err != nil {
		return 0, err
	}
	return inst.InstrumentToken, nil
}

// SetupTelegramTool registers the user's Telegram chat ID for alert notifications.
type SetupTelegramTool struct{}

func (*SetupTelegramTool) Tool() mcp.Tool {
	return mcp.NewTool("setup_telegram",
		mcp.WithDescription("Register your Telegram chat ID for price alert notifications. To get your chat ID: 1) Message @userinfobot on Telegram, 2) It will reply with your chat ID."),
		mcp.WithTitleAnnotation("Setup Telegram"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
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

		if manager.TelegramNotifier() == nil {
			return mcp.NewToolResultError("Telegram notifications are not configured on this server. Contact the server admin."), nil
		}

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "chat_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		chatIDFloat := NewArgParser(args).Float("chat_id", 0)
		if math.IsNaN(chatIDFloat) || math.IsInf(chatIDFloat, 0) || chatIDFloat > float64(math.MaxInt64) || chatIDFloat < float64(math.MinInt64) {
			return mcp.NewToolResultError("Invalid chat_id: must be a valid integer"), nil
		}
		chatID := int64(chatIDFloat)
		if chatID == 0 {
			return mcp.NewToolResultError("Invalid chat ID"), nil
		}

		uc := usecases.NewSetupTelegramUseCase(handler.deps.Telegram.TelegramStore(), manager.Logger)
		if err := uc.Execute(ctx, cqrs.SetupTelegramCommand{Email: email, ChatID: chatID}); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Telegram notifications configured for %s. You'll receive alerts at chat ID %d.", email, chatID)), nil
	}
}

// SetAlertTool creates a price alert for an instrument.
type SetAlertTool struct{}

func (*SetAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("set_alert",
		mcp.WithTitleAnnotation("Set Price Alert"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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

		p := NewArgParser(args)
		instrumentID := p.String("instrument", "")
		targetPrice := p.Float("price", 0)
		directionStr := p.String("direction", "above")
		referencePrice := p.Float("reference_price", 0)

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
		inst, err := handler.deps.Instruments.InstrumentsManager().GetByID(instrumentID)
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
			ltpResp, ltpErr := RetryBrokerCall(func() (kiteconnect.QuoteLTP, error) {
				return kiteSession.Kite.Client.GetLTP(instrumentID)
			}, 2)
			if ltpErr != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch current LTP for reference price: %s", ltpErr)), nil
			}
			ltpData, ok := ltpResp[instrumentID]
			if !ok || ltpData.LastPrice <= 0 {
				return mcp.NewToolResultError(fmt.Sprintf("No LTP available for %s — provide reference_price manually", instrumentID)), nil
			}
			referencePrice = ltpData.LastPrice
		}

		uc := usecases.NewCreateAlertUseCase(
			handler.deps.Alerts.AlertStore(),
			&instrumentResolverAdapter{mgr: manager.Instruments},
			manager.Logger,
		)
		alertID, err := uc.Execute(ctx, cqrs.CreateAlertCommand{
			Email:          email,
			Tradingsymbol:  tradingsymbol,
			Exchange:       exchange,
			TargetPrice:    targetPrice,
			Direction:      directionStr,
			ReferencePrice: referencePrice,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to set alert: %s", err)), nil
		}

		// Auto-start ticker and subscribe instrument
		tickerSvc := handler.deps.Ticker.TickerService()
		tickerMsg := ""
		if !tickerSvc.IsRunning(email) {
			apiKey := handler.deps.Credentials.GetAPIKeyForEmail(email)
			if entry, ok := handler.deps.Tokens.TokenStore().Get(email); ok {
				if startErr := tickerSvc.Start(email, apiKey, entry.AccessToken); startErr != nil {
					manager.Logger.Warn("Failed to auto-start ticker for alert", "email", email, "error", startErr)
				} else {
					tickerMsg = "\nTicker auto-started."
				}
			}
		}
		if tickerSvc.IsRunning(email) {
			if subErr := tickerSvc.Subscribe(email, []uint32{inst.InstrumentToken}, ticker.ModeLTP); subErr != nil {
				manager.Logger.Warn("Failed to auto-subscribe instrument for alert", "email", email, "error", subErr)
			} else {
				tickerMsg += fmt.Sprintf("\nSubscribed %s for real-time alerts.", instrumentID)
			}
		}

		var result string
		if alerts.IsPercentageDirection(direction) {
			result = fmt.Sprintf("Alert set: %s %s %.2f%% from reference %.2f (ID: %s)", instrumentID, directionStr, targetPrice, referencePrice, alertID)
		} else {
			result = fmt.Sprintf("Alert set: %s %s %.2f (ID: %s)", instrumentID, directionStr, targetPrice, alertID)
		}

		if tickerMsg != "" {
			result += tickerMsg
		}

		// Check if Telegram is configured
		if _, ok := handler.deps.Telegram.TelegramStore().GetTelegramChatID(email); !ok {
			result += "\n\nNote: Telegram not configured. Use setup_telegram to receive notifications."
		}

		return mcp.NewToolResultText(result), nil
	}
}

// ListAlertsTool lists all alerts for the current user.
type ListAlertsTool struct{}

func (*ListAlertsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_alerts",
		mcp.WithDescription("List all price alerts for the current user, including triggered and active alerts."),
		mcp.WithTitleAnnotation("List Alerts"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
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

		uc := usecases.NewListAlertsUseCase(handler.deps.Alerts.AlertStore(), manager.Logger)
		alertList, err := uc.Execute(ctx, cqrs.GetAlertsQuery{Email: email})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if len(alertList) == 0 {
			return mcp.NewToolResultText("No alerts configured. Use set_alert to create one."), nil
		}

		return handler.MarshalResponse(map[string]interface{}{
			"alerts": alertList,
		}, "list_alerts")
	}
}

// DeleteAlertTool deletes a price alert by ID.
type DeleteAlertTool struct{}

func (*DeleteAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("delete_alert",
		mcp.WithDescription("Delete a price alert by its ID."),
		mcp.WithTitleAnnotation("Delete Alert"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
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

		alertID := NewArgParser(args).String("alert_id", "")

		uc := usecases.NewDeleteAlertUseCase(handler.deps.Alerts.AlertStore(), manager.Logger)
		if err := uc.Execute(ctx, cqrs.DeleteAlertCommand{Email: email, AlertID: alertID}); err != nil {
			handler.trackToolError(ctx, "delete_alert", "delete_error")
			return mcp.NewToolResultError(err.Error()), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Alert %s deleted.", alertID)), nil
	}
}
