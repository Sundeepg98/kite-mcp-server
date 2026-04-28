package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// StartTickerTool starts a WebSocket stream for live market data.
type StartTickerTool struct{}

func (*StartTickerTool) Tool() mcp.Tool {
	return mcp.NewTool("start_ticker",
		mcp.WithDescription("Start a WebSocket stream for live market data. Requires an active Kite session (call login first). Once started, use subscribe_instruments to add instruments. Only one ticker per user is allowed."),
		mcp.WithTitleAnnotation("Start Ticker"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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
			apiKey := handler.deps.Credentials.GetAPIKeyForEmail(email)
			accessToken := handler.deps.Credentials.GetAccessTokenForEmail(email)

			if accessToken == "" {
				return mcp.NewToolResultError("No access token — please login first"), nil
			}

			if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.StartTickerCommand{
				Email:       email,
				APIKey:      apiKey,
				AccessToken: accessToken,
			}); err != nil {
				handler.trackToolError(ctx, "start_ticker", "start_error")
				return mcp.NewToolResultError(err.Error()), nil
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
		mcp.WithTitleAnnotation("Stop Ticker"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
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

			if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.StopTickerCommand{
				Email: email,
			}); err != nil {
				handler.trackToolError(ctx, "stop_ticker", "stop_error")
				return mcp.NewToolResultError(err.Error()), nil
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
		mcp.WithTitleAnnotation("Ticker Status"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
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

			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.TickerStatusQuery{Email: email})
			if err != nil {
				handler.trackToolError(ctx, "ticker_status", "status_error")
				return mcp.NewToolResultError(err.Error()), nil
			}
			status := raw.(*ticker.Status)

			return handler.MarshalResponse(status, "ticker_status")
		})
	}
}

// SubscribeInstrumentsTool subscribes to instruments for live tick data.
type SubscribeInstrumentsTool struct{}

func (*SubscribeInstrumentsTool) Tool() mcp.Tool {
	return mcp.NewTool("subscribe_instruments",
		mcp.WithDescription("Subscribe to instruments for live WebSocket tick data. The ticker must be started first with start_ticker. Instruments are specified as exchange:tradingsymbol (e.g. 'NSE:INFY')."),
		mcp.WithTitleAnnotation("Subscribe Instruments"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
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

		return handler.WithSession(ctx, "subscribe_instruments", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				email = session.Email
			}
			if email == "" {
				return mcp.NewToolResultError("Email required"), nil
			}

			p := NewArgParser(args)
			instrumentIDs := p.StringArray("instruments")
			if len(instrumentIDs) == 0 {
				return mcp.NewToolResultError("At least one instrument must be specified"), nil
			}

			modeStr := p.String("mode", "full")

			// Resolve instrument IDs to tokens via the InstrumentsManagerProvider port.
			tokens, failed := resolveInstrumentTokens(handler.Instruments(), instrumentIDs)
			if len(tokens) == 0 {
				return mcp.NewToolResultError(fmt.Sprintf("Could not resolve any instruments: %v", failed)), nil
			}

			if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.SubscribeInstrumentsCommand{
				Email:  email,
				Tokens: tokens,
				Mode:   modeStr,
			}); err != nil {
				handler.trackToolError(ctx, "subscribe_instruments", "subscribe_error")
				return mcp.NewToolResultError(err.Error()), nil
			}

			result := fmt.Sprintf("Subscribed to %d instruments in '%s' mode.", len(tokens), modeStr)
			if len(failed) > 0 {
				result += fmt.Sprintf(" Failed to resolve: %v", failed)
			}
			return mcp.NewToolResultText(result), nil
		})
	}
}

// UnsubscribeInstrumentsTool removes instrument subscriptions.
type UnsubscribeInstrumentsTool struct{}

func (*UnsubscribeInstrumentsTool) Tool() mcp.Tool {
	return mcp.NewTool("unsubscribe_instruments",
		mcp.WithDescription("Unsubscribe from instruments to stop receiving live tick data."),
		mcp.WithTitleAnnotation("Unsubscribe Instruments"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
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

		return handler.WithSession(ctx, "unsubscribe_instruments", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)
			if email == "" {
				email = session.Email
			}
			if email == "" {
				return mcp.NewToolResultError("Email required"), nil
			}

			instrumentIDs := NewArgParser(args).StringArray("instruments")
			if len(instrumentIDs) == 0 {
				return mcp.NewToolResultError("At least one instrument must be specified"), nil
			}

			tokens, failed := resolveInstrumentTokens(handler.Instruments(), instrumentIDs)
			if len(tokens) == 0 {
				return mcp.NewToolResultError(fmt.Sprintf("Could not resolve any instruments: %v", failed)), nil
			}

			if _, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.UnsubscribeInstrumentsCommand{
				Email:  email,
				Tokens: tokens,
			}); err != nil {
				handler.trackToolError(ctx, "unsubscribe_instruments", "unsubscribe_error")
				return mcp.NewToolResultError(err.Error()), nil
			}

			result := fmt.Sprintf("Unsubscribed from %d instruments.", len(tokens))
			if len(failed) > 0 {
				result += fmt.Sprintf(" Failed to resolve: %v", failed)
			}
			return mcp.NewToolResultText(result), nil
		})
	}
}

// resolveInstrumentTokens converts exchange:tradingsymbol strings to instrument tokens.
// Phase 3a Batch 2: takes the InstrumentManagerInterface port rather than
// reaching for the *kc.Manager.Instruments concrete field.
func resolveInstrumentTokens(instr kc.InstrumentManagerInterface, instrumentIDs []string) (tokens []uint32, failed []string) {
	if instr == nil {
		return nil, instrumentIDs
	}
	for _, id := range instrumentIDs {
		inst, err := instr.GetByID(id)
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

func init() {
	RegisterInternalTool(&StartTickerTool{})
	RegisterInternalTool(&StopTickerTool{})
	RegisterInternalTool(&SubscribeInstrumentsTool{})
	RegisterInternalTool(&TickerStatusTool{})
	RegisterInternalTool(&UnsubscribeInstrumentsTool{})
}
