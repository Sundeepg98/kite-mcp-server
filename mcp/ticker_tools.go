package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// StartTickerTool starts a WebSocket stream for live market data.
type StartTickerTool struct{}

func (*StartTickerTool) Tool() mcp.Tool {
	return mcp.NewTool("start_ticker",
		mcp.WithDescription("Start a WebSocket stream for live market data. Requires an active Kite session (call login first). Once started, use subscribe_instruments to add instruments. Only one ticker per user is allowed."),
	)
}

func (*StartTickerTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "start_ticker")

		return handler.WithSession(ctx, "start_ticker", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				email = session.Email
			}
			if email == "" {
				return mcp.NewToolResultError("Email required for ticker (OAuth must be enabled)"), nil
			}

			// Resolve API key and access token from manager (client fields are private)
			apiKey := manager.GetAPIKeyForEmail(email)
			accessToken := manager.GetAccessTokenForEmail(email)

			if accessToken == "" {
				return mcp.NewToolResultError("No access token — please login first"), nil
			}

			if err := manager.TickerService().Start(email, apiKey, accessToken); err != nil {
				handler.trackToolError(ctx, "start_ticker", "start_error")
				return mcp.NewToolResultError(fmt.Sprintf("Failed to start ticker: %s", err)), nil
			}

			return mcp.NewToolResultText("Ticker started. Use subscribe_instruments to add instruments for live data."), nil
		})
	}
}

// StopTickerTool stops the user's WebSocket stream.
type StopTickerTool struct{}

func (*StopTickerTool) Tool() mcp.Tool {
	return mcp.NewTool("stop_ticker",
		mcp.WithDescription("Stop the WebSocket stream for live market data."),
	)
}

func (*StopTickerTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "stop_ticker")

		return handler.WithSession(ctx, "stop_ticker", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				email = session.Email
			}
			if email == "" {
				return mcp.NewToolResultError("Email required"), nil
			}

			if err := manager.TickerService().Stop(email); err != nil {
				handler.trackToolError(ctx, "stop_ticker", "stop_error")
				return mcp.NewToolResultError(fmt.Sprintf("Failed to stop ticker: %s", err)), nil
			}

			return mcp.NewToolResultText("Ticker stopped."), nil
		})
	}
}

// TickerStatusTool shows the current ticker connection status and subscriptions.
type TickerStatusTool struct{}

func (*TickerStatusTool) Tool() mcp.Tool {
	return mcp.NewTool("ticker_status",
		mcp.WithDescription("Show the current WebSocket ticker connection status and subscribed instruments."),
	)
}

func (*TickerStatusTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "ticker_status")

		return handler.WithSession(ctx, "ticker_status", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				email = session.Email
			}
			if email == "" {
				return mcp.NewToolResultError("Email required"), nil
			}

			status, err := manager.TickerService().GetStatus(email)
			if err != nil {
				handler.trackToolError(ctx, "ticker_status", "status_error")
				return mcp.NewToolResultError(fmt.Sprintf("Failed to get ticker status: %s", err)), nil
			}

			return handler.MarshalResponse(status, "ticker_status")
		})
	}
}

// SubscribeInstrumentsTool subscribes to instruments for live tick data.
type SubscribeInstrumentsTool struct{}

func (*SubscribeInstrumentsTool) Tool() mcp.Tool {
	return mcp.NewTool("subscribe_instruments",
		mcp.WithDescription("Subscribe to instruments for live WebSocket tick data. The ticker must be started first with start_ticker. Instruments are specified as exchange:tradingsymbol (e.g. 'NSE:INFY')."),
		mcp.WithArray("instruments",
			mcp.Description("List of instruments to subscribe. Eg. ['NSE:INFY', 'NSE:SBIN']"),
			mcp.Required(),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithString("mode",
			mcp.Description("Subscription mode: 'ltp' (last price only), 'quote' (OHLC + volume), 'full' (all fields including market depth)"),
			mcp.Enum("ltp", "quote", "full"),
		),
	)
}

func (*SubscribeInstrumentsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "subscribe_instruments")

		args := request.GetArguments()
		if err := ValidateRequired(args, "instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required"), nil
		}

		instrumentIDs := SafeAssertStringArray(args["instruments"])
		if len(instrumentIDs) == 0 {
			return mcp.NewToolResultError("At least one instrument must be specified"), nil
		}

		modeStr := SafeAssertString(args["mode"], "full")

		// Resolve instrument IDs to tokens using the instruments manager
		tokens, failed := resolveInstrumentTokens(manager, instrumentIDs)
		if len(tokens) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("Could not resolve any instruments: %v", failed)), nil
		}

		// Map mode string to ticker mode
		mode := resolveTickerMode(modeStr)

		if err := manager.TickerService().Subscribe(email, tokens, mode); err != nil {
			handler.trackToolError(ctx, "subscribe_instruments", "subscribe_error")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to subscribe: %s", err)), nil
		}

		result := fmt.Sprintf("Subscribed to %d instruments in '%s' mode.", len(tokens), modeStr)
		if len(failed) > 0 {
			result += fmt.Sprintf(" Failed to resolve: %v", failed)
		}
		return mcp.NewToolResultText(result), nil
	}
}

// UnsubscribeInstrumentsTool removes instrument subscriptions.
type UnsubscribeInstrumentsTool struct{}

func (*UnsubscribeInstrumentsTool) Tool() mcp.Tool {
	return mcp.NewTool("unsubscribe_instruments",
		mcp.WithDescription("Unsubscribe from instruments to stop receiving live tick data."),
		mcp.WithArray("instruments",
			mcp.Description("List of instruments to unsubscribe. Eg. ['NSE:INFY', 'NSE:SBIN']"),
			mcp.Required(),
			mcp.Items(map[string]any{"type": "string"}),
		),
	)
}

func (*UnsubscribeInstrumentsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "unsubscribe_instruments")

		args := request.GetArguments()
		if err := ValidateRequired(args, "instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required"), nil
		}

		instrumentIDs := SafeAssertStringArray(args["instruments"])
		if len(instrumentIDs) == 0 {
			return mcp.NewToolResultError("At least one instrument must be specified"), nil
		}

		tokens, failed := resolveInstrumentTokens(manager, instrumentIDs)
		if len(tokens) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("Could not resolve any instruments: %v", failed)), nil
		}

		if err := manager.TickerService().Unsubscribe(email, tokens); err != nil {
			handler.trackToolError(ctx, "unsubscribe_instruments", "unsubscribe_error")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to unsubscribe: %s", err)), nil
		}

		result := fmt.Sprintf("Unsubscribed from %d instruments.", len(tokens))
		if len(failed) > 0 {
			result += fmt.Sprintf(" Failed to resolve: %v", failed)
		}
		return mcp.NewToolResultText(result), nil
	}
}

// resolveInstrumentTokens converts exchange:tradingsymbol strings to instrument tokens.
func resolveInstrumentTokens(manager *kc.Manager, instrumentIDs []string) (tokens []uint32, failed []string) {
	for _, id := range instrumentIDs {
		inst, err := manager.Instruments.GetByID(id)
		if err != nil {
			failed = append(failed, id)
			continue
		}
		tokens = append(tokens, inst.InstrumentToken)
	}
	return
}

// resolveTickerMode converts a mode string to the kiteticker Mode type.
func resolveTickerMode(mode string) ticker.Mode {
	switch mode {
	case "ltp":
		return ticker.ModeLTP
	case "quote":
		return ticker.ModeQuote
	default:
		return ticker.ModeFull
	}
}
