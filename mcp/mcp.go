package mcp

import (
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

type Tool interface {
	Tool() gomcp.Tool
	Handler(*kc.Manager) server.ToolHandlerFunc
}

// GetAllTools returns all available tools for registration, including
// any externally registered plugins.
func GetAllTools() []Tool {
	builtIn := []Tool{
		// Tools for setting up the client
		&LoginTool{},
		&OpenDashboardTool{},
		&TestIPWhitelistTool{},

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
		&BacktestStrategyTool{},

		// Tools for real-time market data (WebSocket ticker)
		&StartTickerTool{},
		&StopTickerTool{},
		&TickerStatusTool{},
		&SubscribeInstrumentsTool{},
		&UnsubscribeInstrumentsTool{},

		// Tools for price alerts (custom, MCP server-side)
		&SetupTelegramTool{},
		&SetAlertTool{},
		&CompositeAlertTool{},
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
		&SectorExposureTool{},
		&VolumeSpikeDetectorTool{},

		// Portfolio rebalancing
		&PortfolioRebalanceTool{},

		// Tax analysis
		&TaxHarvestTool{},

		// Dividend & corporate actions
		&DividendCalendarTool{},

		// Earnings-call analysis (frames the LLM — returns pointer + themes,
		// LLM fetches transcript client-side via WebFetch / Tavily).
		&AnalyzeConcallTool{},

		// get_fii_dii_flow — FII/DII daily institutional flow (frames the LLM;
		// returns NSE + Moneycontrol URL pointers, LLM fetches via WebFetch / Tavily).
		&GetFIIDIIFlowTool{},

		// server_version — build SHA, build time, region, Go version. For
		// debugging which deployment you're connected to (complements
		// server_metrics which covers per-tool latency/errors).
		&ServerVersionTool{},

		// peer_compare — side-by-side fundamental-strength comparison for 2-6
		// stocks (PEG, Piotroski F-score, Altman Z-score + key ratios). Frames
		// the LLM: returns Screener.in URL pointers + formulas, LLM fetches
		// fundamentals via WebFetch/Tavily and computes scores client-side.
		&PeerCompareTool{},

		// SEBI compliance
		&SEBIComplianceTool{},

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

		// Self-service account management
		&DeleteMyAccountTool{},
		&UpdateMyCredentialsTool{},

		// Per-user session management (not admin-only — each user sees their own)
		&ListMCPSessionsTool{},
		&RevokeMCPSessionTool{},

		// Server observability
		&ServerMetricsTool{},
		&GetOrderProjectionTool{},
		&GetOrderHistoryReconstitutedTool{},
		&GetAlertHistoryReconstitutedTool{},
		&GetPositionHistoryReconstitutedTool{},

		// Admin tools (admin-only, gated by IsAdmin check in handlers)
		&AdminListUsersTool{},
		&AdminGetUserTool{},
		&AdminGetUserBaselineTool{},
		&AdminStatsCacheInfoTool{},
		&AdminServerStatusTool{},
		&AdminGetRiskStatusTool{},
		&AdminSuspendUserTool{},
		&AdminActivateUserTool{},
		&AdminChangeRoleTool{},
		&AdminFreezeUserTool{},
		&AdminUnfreezeUserTool{},
		&AdminFreezeGlobalTool{},
		&AdminUnfreezeGlobalTool{},
		&AdminInviteFamilyMemberTool{},
		&AdminListFamilyTool{},
		&AdminRemoveFamilyMemberTool{},
		&AdminSetBillingTierTool{},
	}

	// Append registered plugins
	registry.mu.Lock()
	if len(registry.plugins) > 0 {
		builtIn = append(builtIn, registry.plugins...)
	}
	registry.mu.Unlock()

	return builtIn
}

// parseExcludedTools parses a comma-separated string of tool names and returns a set of excluded tools.
// This function is exported for testing purposes to ensure tests use the exact same logic as production.
func parseExcludedTools(excludedTools string) map[string]bool {
	excludedSet := make(map[string]bool)
	if excludedTools != "" {
		for toolName := range strings.SplitSeq(excludedTools, ",") {
			toolName = strings.TrimSpace(toolName)
			if toolName != "" {
				excludedSet[toolName] = true
			}
		}
	}
	return excludedSet
}

// tradingToolNames is the canonical set of tools that actually place,
// modify, or cancel orders/positions on a real Kite account. When the
// hosted multi-user deployment runs with ENABLE_TRADING=false these
// tools are stripped from the registered set so the server cannot
// submit orders on a user's behalf — avoiding NSE/INVG/69255 Annexure I
// Para 2.8 "Algo Provider" classification. Local single-user builds
// opt back in by setting ENABLE_TRADING=true.
//
// The set is intentionally a package-level variable (not a constant map
// literal) so callers — including tests — can read it without copying.
// Do NOT mutate at runtime.
var tradingToolNames = map[string]bool{
	// Equity/F&O order lifecycle
	"place_order":      true,
	"modify_order":     true,
	"cancel_order":     true,
	"convert_position": true,
	// Exit helpers (auto-fire place_order / modify_order under the hood)
	"close_position":      true,
	"close_all_positions": true,
	// GTT order lifecycle
	"place_gtt_order":  true,
	"modify_gtt_order": true,
	"delete_gtt_order": true,
	// Trailing stop-loss (fires modify_order on each trail step)
	"set_trailing_stop":    true,
	"cancel_trailing_stop": true,
	// Native Kite server-side alerts (ATO can auto-place orders)
	"place_native_alert":  true,
	"modify_native_alert": true,
	"delete_native_alert": true,
	// Mutual fund order/SIP lifecycle
	"place_mf_order":  true,
	"cancel_mf_order": true,
	"place_mf_sip":    true,
	"cancel_mf_sip":   true,
}

// IsTradingTool reports whether a tool name is an order-placement tool
// that would be gated by the ENABLE_TRADING flag. Exported so other
// packages (e.g. observability, dashboards) can label tools consistently.
func IsTradingTool(name string) bool {
	return tradingToolNames[name]
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

// filterToolsWithGating combines explicit EXCLUDED_TOOLS entries with
// the ENABLE_TRADING gate. Returns (keptTools, registeredCount, gatedCount).
// gatedCount counts tools removed specifically by the trading gate (not
// the excluded set) — an operator-facing number so the startup log can
// show "N trading tools gated (ENABLE_TRADING=false)". Tools already
// excluded are not double-counted against gatedCount.
func filterToolsWithGating(allTools []Tool, excludedSet map[string]bool, enableTrading bool) ([]Tool, int, int) {
	kept := make([]Tool, 0, len(allTools))
	gated := 0
	for _, tool := range allTools {
		name := tool.Tool().Name
		if excludedSet[name] {
			// Already excluded — drop, don't count under gated.
			continue
		}
		if !enableTrading && tradingToolNames[name] {
			gated++
			continue
		}
		kept = append(kept, tool)
	}
	return kept, len(kept), gated
}

func RegisterTools(srv *server.MCPServer, manager *kc.Manager, excludedTools string, auditStore *audit.Store, logger *slog.Logger, enableTrading bool) {
	// Parse excluded tools list
	excludedSet := parseExcludedTools(excludedTools)

	// Log excluded tools
	for toolName := range excludedSet {
		logger.Info("Excluding tool from registration", "tool", toolName)
	}

	// Apply trading gate + exclusions.
	allTools := GetAllTools()
	filteredTools, registeredCount, gatedCount := filterToolsWithGating(allTools, excludedSet, enableTrading)
	// excludedCount is recomputed separately so the startup log keeps
	// its original semantics (explicit EXCLUDED_TOOLS only).
	excludedCount := 0
	for _, tool := range allTools {
		if excludedSet[tool.Tool().Name] {
			excludedCount++
		}
	}

	if !enableTrading {
		logger.Warn("ENABLE_TRADING=false — order-placement tools gated (hosted/multi-user safe mode)",
			"gated_count", gatedCount)
	}

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

	// Compute the tool-description integrity manifest (sha256 per tool)
	// so operators can detect wire-level tampering ("line jumping" /
	// tool-poisoning attacks from a hostile proxy — see integrity.go).
	manifest := ComputeToolManifest(filteredTools)
	storeToolManifest(manifest)
	logger.Info("Tool integrity manifest computed",
		"tools", len(manifest.Tools),
		"hash_bytes", manifest.TotalHashBytes(),
		"logged_at", manifest.LoggedAt.Format(time.RFC3339))

	logger.Info("Tool registration complete",
		"registered", registeredCount,
		"excluded", excludedCount,
		"gated_trading", gatedCount,
		"trading_enabled", enableTrading,
		"total_available", len(allTools))
}
