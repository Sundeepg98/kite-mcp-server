package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
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
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		engine := manager.PaperEngine()
		if engine == nil {
			return gomcp.NewToolResultError("Paper trading not configured"), nil
		}
		args := request.GetArguments()
		enable, _ := args["enable"].(bool)
		initialCash := SafeAssertFloat64(args["initial_cash"], 10000000)

		if enable {
			if err := engine.Enable(email, initialCash); err != nil {
				return gomcp.NewToolResultError("Failed to enable: " + err.Error()), nil
			}
			return gomcp.NewToolResultText(fmt.Sprintf("Paper trading ENABLED. Virtual cash: Rs %.0f. All orders now execute against your virtual portfolio.", initialCash)), nil
		}
		if err := engine.Disable(email); err != nil {
			return gomcp.NewToolResultError("Failed to disable: " + err.Error()), nil
		}
		return gomcp.NewToolResultText("Paper trading DISABLED. Orders now execute against the real Kite API."), nil
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
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		engine := manager.PaperEngine()
		if engine == nil {
			return gomcp.NewToolResultError("Paper trading not configured"), nil
		}
		status, err := engine.Status(email)
		if err != nil {
			return gomcp.NewToolResultError("Failed to get status: " + err.Error()), nil
		}
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
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return gomcp.NewToolResultError("Not authenticated"), nil
		}
		engine := manager.PaperEngine()
		if engine == nil {
			return gomcp.NewToolResultError("Paper trading not configured"), nil
		}
		if err := engine.Reset(email); err != nil {
			return gomcp.NewToolResultError("Failed to reset: " + err.Error()), nil
		}
		return gomcp.NewToolResultText("Paper trading portfolio RESET. All positions, holdings, and orders cleared. Cash restored to initial amount."), nil
	}
}
