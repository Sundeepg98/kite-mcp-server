package mcp

import (
	"log/slog"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

type Tool interface {
	Tool() gomcp.Tool
	Handler(*kc.Manager) server.ToolHandlerFunc
}

// GetAllTools returns all available tools for registration
func GetAllTools() []Tool {
	return []Tool{
		// Tools for setting up the client
		&LoginTool{},
		&OpenDashboardTool{},

		// Tools that get data from Kite Connect
		&ProfileTool{},
		&MarginsTool{},
		&HoldingsTool{},
		&PositionsTool{},
		&TradesTool{},
		&OrdersTool{},
		&OrderHistoryTool{},
		&OrderTradesTool{},
		&GTTOrdersTool{},
		&MFHoldingsTool{},
		&MFOrdersTool{},
		&MFSIPsTool{},
		&PlaceMFOrderTool{},
		&CancelMFOrderTool{},
		&PlaceMFSIPTool{},
		&CancelMFSIPTool{},

		// Tools for market data
		&QuotesTool{},
		&InstrumentsSearchTool{},
		&HistoricalDataTool{},
		&LTPTool{},
		&OHLCTool{},
		&OptionChainTool{},
		&OptionsGreeksTool{},
		&OptionsStrategyTool{},
		&TechnicalIndicatorsTool{},

		// Tools for real-time market data (WebSocket ticker)
		&StartTickerTool{},
		&StopTickerTool{},
		&TickerStatusTool{},
		&SubscribeInstrumentsTool{},
		&UnsubscribeInstrumentsTool{},

		// Tools for price alerts (custom, MCP server-side)
		&SetupTelegramTool{},
		&SetAlertTool{},
		&ListAlertsTool{},
		&DeleteAlertTool{},

		// Native alerts (Zerodha server-side, survive MCP server restarts)
		&PlaceNativeAlertTool{},
		&ListNativeAlertsTool{},
		&ModifyNativeAlertTool{},
		&DeleteNativeAlertTool{},
		&GetNativeAlertHistoryTool{},

		// Trailing stop-loss tools
		&SetTrailingStopTool{},
		&ListTrailingStopsTool{},
		&CancelTrailingStopTool{},

		// Watchlist tools
		&CreateWatchlistTool{},
		&DeleteWatchlistTool{},
		&AddToWatchlistTool{},
		&RemoveFromWatchlistTool{},
		&GetWatchlistTool{},
		&ListWatchlistsTool{},

		// P&L journal
		&GetPnLJournalTool{},

		// Trading context (unified snapshot — start here)
		&TradingContextTool{},

		// Portfolio analytics
		&PortfolioSummaryTool{},
		&PortfolioConcentrationTool{},
		&PositionAnalysisTool{},

		// Portfolio rebalancing
		&PortfolioRebalanceTool{},

		// Tax analysis
		&TaxHarvestTool{},

		// Paper trading management
		&PaperTradingToggleTool{},
		&PaperTradingStatusTool{},
		&PaperTradingResetTool{},

		// Pre-trade composite check (replaces 5 separate tool calls)
		&PreTradeCheckTool{},

		// Tools for margin and charges calculation
		&OrderMarginsTool{},
		&BasketMarginsTool{},
		&OrderChargesTool{},

		// Tools that post data to Kite Connect
		&PlaceOrderTool{},
		&ModifyOrderTool{},
		&CancelOrderTool{},
		&ConvertPositionTool{},
		&ClosePositionTool{},
		&CloseAllPositionsTool{},
		&PlaceGTTOrderTool{},
		&ModifyGTTOrderTool{},
		&DeleteGTTOrderTool{},
	}
}

// parseExcludedTools parses a comma-separated string of tool names and returns a set of excluded tools.
// This function is exported for testing purposes to ensure tests use the exact same logic as production.
func parseExcludedTools(excludedTools string) map[string]bool {
	excludedSet := make(map[string]bool)
	if excludedTools != "" {
		excluded := strings.Split(excludedTools, ",")
		for _, toolName := range excluded {
			toolName = strings.TrimSpace(toolName)
			if toolName != "" {
				excludedSet[toolName] = true
			}
		}
	}
	return excludedSet
}

// filterTools returns tools that are not in the excluded set, along with counts.
// Returns (filteredTools, registeredCount, excludedCount).
// This function is exported for testing purposes to ensure tests use the exact same logic as production.
func filterTools(allTools []Tool, excludedSet map[string]bool) ([]Tool, int, int) {
	filteredTools := make([]Tool, 0, len(allTools))
	excludedCount := 0

	for _, tool := range allTools {
		toolName := tool.Tool().Name
		if excludedSet[toolName] {
			excludedCount++
			continue
		}
		filteredTools = append(filteredTools, tool)
	}

	return filteredTools, len(filteredTools), excludedCount
}

func RegisterTools(srv *server.MCPServer, manager *kc.Manager, excludedTools string, auditStore *audit.Store, logger *slog.Logger) {
	// Parse excluded tools list
	excludedSet := parseExcludedTools(excludedTools)

	// Log excluded tools
	for toolName := range excludedSet {
		logger.Info("Excluding tool from registration", "tool", toolName)
	}

	// Filter tools
	allTools := GetAllTools()
	filteredTools, registeredCount, excludedCount := filterTools(allTools, excludedSet)

	// Register filtered tools, injecting _meta["ui/resourceUri"] for MCP Apps
	// where the tool has an associated dashboard page.
	for _, tool := range filteredTools {
		t := tool.Tool()
		if uri := resourceURIForTool(t.Name); uri != "" {
			t = withAppUI(t, uri)
		}
		srv.AddTool(t, tool.Handler(manager))
	}

	// Register widget pages as MCP App resources (ui:// scheme).
	RegisterAppResources(srv, manager, auditStore, logger)

	// Register MCP prompts for common trading workflows.
	RegisterPrompts(srv, manager)

	logger.Info("Tool registration complete",
		"registered", registeredCount,
		"excluded", excludedCount,
		"total_available", len(allTools))
}
