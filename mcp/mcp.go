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
//
// Migration path (Investment J): the literal slice below is being
// incrementally drained as `<feature>_tools.go` files migrate to
// init()-based RegisterInternalTool calls. New tools should NOT be
// appended to this slice — register them via init() in their feature
// file instead. Once empty, GetAllTools() collapses to a registry +
// plugin merge.
//
// GetAllTools is a backward-compat shim around GetAllToolsForRegistry
// that consults the package-level DefaultRegistry for plugin tools.
// Production callers that own a per-App registry should call
// GetAllToolsForRegistry(app.Registry()) directly — that path is
// isolated from cross-App plugin registrations (B77 Phase 2).
func GetAllTools() []Tool {
	return GetAllToolsForRegistry(DefaultRegistry)
}

// GetAllToolsForRegistry returns the merged list of internal init()-time-
// registered tools, package-baseline built-in tools, and the App-scoped
// plugin tools held by reg. Unlike GetAllTools, this variant does NOT
// consult DefaultRegistry — two parallel Apps using NewRegistry()
// instances will see strictly disjoint plugin sets.
//
// reg may be nil — a nil registry is treated as "no plugins"; only
// internalToolRegistry + the package-baseline tools are returned. This
// keeps the read-side paths (e.g. app/http.go status pages that count
// tools) defensive against a wiring regression that left app.registry
// unset.
func GetAllToolsForRegistry(reg *Registry) []Tool {
	internalToolRegistryMu.Lock()
	registered := append([]Tool(nil), internalToolRegistry...)
	internalToolRegistryMu.Unlock()

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

		// (Portfolio rebalancing → portfolio_analysis: registered via init() in
		// rebalance_tool.go; Tax analysis → tax_loss_analysis: registered via
		// init() in tax_tools.go — Investment J migration in progress.)

		// Earnings-call analysis (frames the LLM — returns pointer + themes,
		// LLM fetches transcript client-side via WebFetch / Tavily).
		&AnalyzeConcallTool{},

		// get_fii_dii_flow — FII/DII daily institutional flow (frames the LLM;
		// returns NSE + Moneycontrol URL pointers, LLM fetches via WebFetch / Tavily).
		&GetFIIDIIFlowTool{},

		// peer_compare — side-by-side fundamental-strength comparison for 2-6
		// stocks (PEG, Piotroski F-score, Altman Z-score + key ratios). Frames
		// the LLM: returns Screener.in URL pointers + formulas, LLM fetches
		// fundamentals via WebFetch/Tavily and computes scores client-side.
		&PeerCompareTool{},

		// Paper trading management
		&PaperTradingToggleTool{},
		&PaperTradingStatusTool{},
		&PaperTradingResetTool{},

		// (Pre-trade composite check → order_risk_report: registered via init()
		// in pretrade_tool.go — Investment J migration in progress.)

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
		&AdminListAnomalyFlagsTool{},
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

	// Prepend init()-registered tools (Investment J — see migration path
	// note above). Order matters only for the SHA256 surface lock test
	// indirectly via the sorted-name list it computes; the wire-protocol
	// itself is order-insensitive.
	if len(registered) > 0 {
		builtIn = append(registered, builtIn...)
	}

	// Append App-scoped plugin tools from the supplied registry. Skips
	// the consult when reg is nil — see GetAllToolsForRegistry doc.
	if reg != nil {
		if plugins := reg.Tools(); len(plugins) > 0 {
			builtIn = append(builtIn, plugins...)
		}
	}

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

// RegisterTools is the legacy/shim entry-point — consults DefaultRegistry
// for plugin tools. Production callers that own a per-App registry should
// use RegisterToolsForRegistry directly to keep tool sets App-isolated
// (B77 Phase 2).
func RegisterTools(srv *server.MCPServer, manager *kc.Manager, excludedTools string, auditStore *audit.Store, logger *slog.Logger, enableTrading bool) {
	RegisterToolsForRegistry(srv, manager, excludedTools, auditStore, logger, enableTrading, DefaultRegistry)
}

// RegisterToolsForRegistry is the App-isolated variant — plugin tools
// come from the supplied registry rather than DefaultRegistry. wire.go
// uses this with app.registry so two parallel Apps in one process see
// disjoint tool sets without polluting each other.
//
// reg may be nil — see GetAllToolsForRegistry for the nil semantics.
func RegisterToolsForRegistry(srv *server.MCPServer, manager *kc.Manager, excludedTools string, auditStore *audit.Store, logger *slog.Logger, enableTrading bool, reg *Registry) {
	// Parse excluded tools list
	excludedSet := parseExcludedTools(excludedTools)

	// Log excluded tools
	for toolName := range excludedSet {
		logger.Info("Excluding tool from registration", "tool", toolName)
	}

	// Apply trading gate + exclusions.
	allTools := GetAllToolsForRegistry(reg)
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

	// Register curated repo documentation as MCP Resources (doc:// scheme).
	// Resolves the repo root at runtime via go.mod walk-up; deployments
	// that don't ship the source tree (e.g. distroless Docker images)
	// simply end up with an empty doc resource list (warnings logged).
	if repoRoot, err := findRepoRoot(); err == nil {
		RegisterDocResources(srv, repoRoot, logger)
	} else {
		logger.Warn("Skipping doc resources — repo root not found (likely running without source tree)",
			"error", err)
	}

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
