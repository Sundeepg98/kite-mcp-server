package mcp

import (
	"context"
	"encoding/json"
	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// PaperTradingToggleTool enables or disables paper trading mode.
type PaperTradingToggleTool struct{}

func (*PaperTradingToggleTool) Tool() gomcp.Tool {
	return gomcp.NewTool("paper_trading_toggle",
		gomcp.WithDescription("Enable or disable paper trading mode. When enabled, all order tools execute against a virtual portfolio with fake money. Real market data is still used for prices."),
		gomcp.WithTitleAnnotation("Toggle Paper Trading"),
		gomcp.WithDestructiveHintAnnotation(false),
		gomcp.WithBoolean("enable", gomcp.Description("true to enable paper mode, false to disable"), gomcp.Required()),
		gomcp.WithNumber("initial_cash", gomcp.Description("Initial virtual cash in INR (default: 10000000 = Rs 1 crore)")),
	)
}

func (*PaperTradingToggleTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		if handler.deps.Paper.PaperEngine() == nil {
			return gomcp.NewToolResultError("Paper trading requires database configuration (ALERT_DB_PATH). Contact the server admin."), nil
		}
		args := request.GetArguments()
		enable, _ := args["enable"].(bool)
		initialCash := NewArgParser(args).Float("initial_cash", 10000000)

		raw, err := manager.CommandBus().DispatchWithResult(ctx, cqrs.PaperTradingToggleCommand{
			Email:       email,
			Enable:      enable,
			InitialCash: initialCash,
		})
		if err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}
		msg, _ := raw.(string)
		return gomcp.NewToolResultText(msg), nil
	}
}

// PaperTradingStatusTool shows current paper trading state.
type PaperTradingStatusTool struct{}

func (*PaperTradingStatusTool) Tool() gomcp.Tool {
	return gomcp.NewTool("paper_trading_status",
		gomcp.WithDescription("Show the current paper trading status including mode, virtual cash balance, open positions, holdings, and pending orders."),
		gomcp.WithTitleAnnotation("Paper Trading Status"),
		gomcp.WithReadOnlyHintAnnotation(true),
	)
}

func (*PaperTradingStatusTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		engine := handler.deps.Paper.PaperEngine()
		if engine == nil {
			return gomcp.NewToolResultError("Paper trading requires database configuration (ALERT_DB_PATH). Contact the server admin."), nil
		}

		raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.PaperTradingStatusQuery{Email: email})
		if err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}
		status := raw.(map[string]any)
		jsonBytes, err := json.Marshal(status)
		if err != nil {
			return gomcp.NewToolResultError("Failed to marshal status: " + err.Error()), nil
		}
		return gomcp.NewToolResultStructured(status, string(jsonBytes)), nil
	}
}

// PaperTradingResetTool resets the virtual portfolio.
type PaperTradingResetTool struct{}

func (*PaperTradingResetTool) Tool() gomcp.Tool {
	return gomcp.NewTool("paper_trading_reset",
		gomcp.WithDescription("Reset the virtual paper trading portfolio. Clears all positions, holdings, orders, and restores cash to the initial amount."),
		gomcp.WithTitleAnnotation("Reset Paper Trading"),
		gomcp.WithDestructiveHintAnnotation(true),
	)
}

func (*PaperTradingResetTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		if handler.deps.Paper.PaperEngine() == nil {
			return gomcp.NewToolResultError("Paper trading requires database configuration (ALERT_DB_PATH). Contact the server admin."), nil
		}

		if _, err := manager.CommandBus().DispatchWithResult(ctx, cqrs.PaperTradingResetCommand{Email: email}); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}
		return gomcp.NewToolResultText("Paper trading portfolio RESET. All positions, holdings, and orders cleared. Cash restored to initial amount."), nil
	}
}
