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

// SetTrailingStopTool creates a trailing stop-loss that automatically modifies
// an existing SL/SL-M order as the price moves favorably.
type SetTrailingStopTool struct{}

func (*SetTrailingStopTool) Tool() mcp.Tool {
	return mcp.NewTool("set_trailing_stop",
		mcp.WithDescription("Set a trailing stop-loss on an EXISTING SL/SL-M order. "+
			"As the price moves favorably, the stop-loss trigger price is automatically adjusted. "+
			"For a long position: the stop trails upward as price rises. "+
			"For a short position: the stop trails downward as price falls. "+
			"Requires: 1) An existing SL/SL-M order (place one first), 2) The ticker running with the instrument subscribed. "+
			"The order is modified at most once every 30 seconds to avoid API rate limits."),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("instrument",
			mcp.Description("Instrument in exchange:tradingsymbol format (e.g. 'NSE:INFY')"),
			mcp.Required(),
		),
		mcp.WithString("order_id",
			mcp.Description("The order ID of the existing SL/SL-M order to trail"),
			mcp.Required(),
		),
		mcp.WithString("direction",
			mcp.Description("Position direction: 'long' (trailing stop moves up) or 'short' (trailing stop moves down)"),
			mcp.Required(),
			mcp.Enum("long", "short"),
		),
		mcp.WithNumber("trail_amount",
			mcp.Description("Absolute trail distance in rupees (e.g., 20.0). Mutually exclusive with trail_pct."),
		),
		mcp.WithNumber("trail_pct",
			mcp.Description("Percentage trail distance (e.g., 1.5 for 1.5%). Mutually exclusive with trail_amount."),
		),
		mcp.WithNumber("current_stop",
			mcp.Description("The current trigger price of the SL order. If omitted, fetched from order history."),
		),
		mcp.WithNumber("reference_price",
			mcp.Description("Initial reference price (high water mark). If omitted, the current LTP is used."),
		),
		mcp.WithString("variety",
			mcp.Description("Order variety of the SL order"),
			mcp.DefaultString("regular"),
			mcp.Enum("regular", "co", "amo"),
		),
	)
}

func (*SetTrailingStopTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "set_trailing_stop")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "instrument", "order_id", "direction"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		instrumentID := SafeAssertString(args["instrument"], "")
		orderID := SafeAssertString(args["order_id"], "")
		direction := SafeAssertString(args["direction"], "")
		trailAmount := SafeAssertFloat64(args["trail_amount"], 0)
		trailPct := SafeAssertFloat64(args["trail_pct"], 0)
		currentStop := SafeAssertFloat64(args["current_stop"], 0)
		referencePrice := SafeAssertFloat64(args["reference_price"], 0)
		variety := SafeAssertString(args["variety"], "regular")

		if trailAmount <= 0 && trailPct <= 0 {
			return mcp.NewToolResultError("Either trail_amount or trail_pct must be provided and positive"), nil
		}
		if trailAmount > 0 && trailPct > 0 {
			return mcp.NewToolResultError("Provide either trail_amount or trail_pct, not both"), nil
		}
		if trailPct > 50 {
			return mcp.NewToolResultError("trail_pct cannot exceed 50%"), nil
		}

		// Resolve instrument
		parts := strings.SplitN(instrumentID, ":", 2)
		if len(parts) != 2 {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid instrument format: %s (expected exchange:symbol)", instrumentID)), nil
		}
		exchange := parts[0]

		inst, err := manager.Instruments.GetByID(instrumentID)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Instrument not found: %s", instrumentID)), nil
		}

		// If current_stop not provided, try to fetch from order history
		if currentStop <= 0 || referencePrice <= 0 {
			return handler.WithSession(ctx, "set_trailing_stop", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
				if currentStop <= 0 {
					history, histErr := session.Kite.Client.GetOrderHistory(orderID)
					if histErr != nil {
						return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch order history for %s: %s. Please provide current_stop manually.", orderID, histErr)), nil
					}
					if len(history) > 0 {
						latest := history[len(history)-1]
						currentStop = latest.TriggerPrice
						if currentStop <= 0 {
							return mcp.NewToolResultError("Could not determine trigger price from order history. Please provide current_stop manually."), nil
						}
					}
				}

				if referencePrice <= 0 {
					ltpResp, ltpErr := session.Kite.Client.GetLTP(instrumentID)
					if ltpErr != nil {
						return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch LTP: %s. Please provide reference_price manually.", ltpErr)), nil
					}
					ltpData, ok := ltpResp[instrumentID]
					if !ok || ltpData.LastPrice <= 0 {
						return mcp.NewToolResultError("No LTP available. Please provide reference_price manually."), nil
					}
					referencePrice = ltpData.LastPrice
				}

				return doSetTrailingStop(manager, email, exchange, inst.Tradingsymbol, inst.InstrumentToken,
					orderID, variety, direction, trailAmount, trailPct, currentStop, referencePrice)
			})
		}

		return doSetTrailingStop(manager, email, exchange, inst.Tradingsymbol, inst.InstrumentToken,
			orderID, variety, direction, trailAmount, trailPct, currentStop, referencePrice)
	}
}

func doSetTrailingStop(manager *kc.Manager, email, exchange, tradingsymbol string, instrumentToken uint32,
	orderID, variety, direction string, trailAmount, trailPct, currentStop, referencePrice float64) (*mcp.CallToolResult, error) {

	tsManager := manager.TrailingStopManager()
	if tsManager == nil {
		return mcp.NewToolResultError("Trailing stop manager not available (requires database persistence)"), nil
	}

	ts := &alerts.TrailingStop{
		Email:           email,
		Exchange:        exchange,
		Tradingsymbol:   tradingsymbol,
		InstrumentToken: instrumentToken,
		OrderID:         orderID,
		Variety:         variety,
		TrailAmount:     trailAmount,
		TrailPct:        trailPct,
		Direction:       direction,
		HighWaterMark:   referencePrice,
		CurrentStop:     currentStop,
	}

	id, err := tsManager.Add(ts)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to set trailing stop: %s", err)), nil
	}

	var trailDesc string
	if trailPct > 0 {
		trailDesc = fmt.Sprintf("%.2f%%", trailPct)
	} else {
		trailDesc = fmt.Sprintf("Rs.%.2f", trailAmount)
	}

	result := fmt.Sprintf("Trailing stop set (ID: %s)\n"+
		"Instrument: %s:%s\n"+
		"Order: %s (%s)\n"+
		"Direction: %s | Trail: %s\n"+
		"Current stop: %.2f | Reference price: %.2f\n"+
		"The SL order will be modified automatically as price moves favorably (max once per 30s).",
		id, exchange, tradingsymbol, orderID, variety,
		direction, trailDesc, currentStop, referencePrice)

	if !manager.TickerService().IsRunning(email) {
		result += "\n\nWARNING: Ticker not running. Use start_ticker and subscribe_instruments for real-time trailing."
	}

	return mcp.NewToolResultText(result), nil
}

// ListTrailingStopsTool lists all trailing stops for the current user.
type ListTrailingStopsTool struct{}

func (*ListTrailingStopsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_trailing_stops",
		mcp.WithDescription("List all trailing stop-losses for the current user, including active and deactivated."),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

func (*ListTrailingStopsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "list_trailing_stops")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		tsManager := manager.TrailingStopManager()
		if tsManager == nil {
			return mcp.NewToolResultError("Trailing stop manager not available"), nil
		}

		stops := tsManager.List(email)
		if len(stops) == 0 {
			return mcp.NewToolResultText("No trailing stops configured. Use set_trailing_stop to create one."), nil
		}

		return handler.MarshalResponse(stops, "list_trailing_stops")
	}
}

// CancelTrailingStopTool deactivates a trailing stop.
type CancelTrailingStopTool struct{}

func (*CancelTrailingStopTool) Tool() mcp.Tool {
	return mcp.NewTool("cancel_trailing_stop",
		mcp.WithDescription("Cancel (deactivate) a trailing stop-loss. The underlying SL order remains unchanged."),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithString("trailing_stop_id",
			mcp.Description("The trailing stop ID to cancel (from list_trailing_stops)"),
			mcp.Required(),
		),
	)
}

func (*CancelTrailingStopTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "cancel_trailing_stop")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "trailing_stop_id"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		tsID := SafeAssertString(args["trailing_stop_id"], "")
		tsManager := manager.TrailingStopManager()
		if tsManager == nil {
			return mcp.NewToolResultError("Trailing stop manager not available"), nil
		}

		if err := tsManager.Cancel(email, tsID); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to cancel trailing stop: %s", err)), nil
		}

		return mcp.NewToolResultText(fmt.Sprintf("Trailing stop %s cancelled. The underlying SL order remains in place.", tsID)), nil
	}
}
