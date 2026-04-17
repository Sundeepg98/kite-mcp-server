package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"math"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// UICapabilityExtensionKey is the MCP Apps capability key that clients
// advertise in `initialize.capabilities.extensions` when they can render
// `ui://` resources as inline widgets (Claude.ai web, Claude Desktop,
// ChatGPT, VS Code Copilot, Goose). Hosts that do NOT advertise this key
// (Claude Code, Windsurf, Cursor pre-2.6, Zed, 5ire, Cline) receive noisy
// fallback text when the server returns widget resource references — so
// we strip `_meta["ui/resourceUri"]` from tool listings for those clients.
//
// Protocol reference: MCP 2026-01-26 spec, section on client extensions.
const UICapabilityExtensionKey = "io.modelcontextprotocol/ui"

// uiMetaKey is the flat `_meta` key that points a tool response at a
// ui:// resource. Kept in sync with withAppUI's key below.
const uiMetaKey = "ui/resourceUri"

// clientSupportsUI reports whether the given client capabilities
// advertise MCP Apps widget support.
//
// Detection order:
//  1. Operator kill-switch: MCP_UI_ENABLED=false disables widgets for
//     every client regardless of advertisement.
//  2. Capability advertisement: returns true if `extensions` or
//     `experimental` contains the MCP Apps extension key.
//
// Fail-closed on missing advertisement: clients that do NOT advertise
// the extension get widgets stripped. This is intentional — per the
// research, unsupported hosts (Claude Code, Windsurf, Cursor pre-2.6,
// Zed, 5ire, Cline) emit noisy fallback text otherwise. The env var
// remains as a forced-disable kill switch (e.g., if a widget release
// is buggy in production), but cannot force-enable on a client that
// didn't advertise — that would reintroduce the noise bug.
func clientSupportsUI(caps gomcp.ClientCapabilities) bool {
	if os.Getenv("MCP_UI_ENABLED") == "false" {
		return false
	}
	if caps.Extensions != nil {
		if _, ok := caps.Extensions[UICapabilityExtensionKey]; ok {
			return true
		}
	}
	if caps.Experimental != nil {
		if _, ok := caps.Experimental[UICapabilityExtensionKey]; ok {
			return true
		}
	}
	return false
}

// stripUIResourceURIFromTools returns a copy of the given tools with the
// `ui/resourceUri` key removed from each tool's `_meta` block. Tools
// without _meta, or whose _meta has no ui/resourceUri key, are copied
// unchanged. The original tools are NOT mutated — we allocate fresh
// `_meta` maps so concurrent list_tools calls from UI-capable sessions
// still see the full metadata.
//
// Used by the OnAfterListTools hook installed in RegisterAppResources
// to quiet non-widget clients (Claude Code, Windsurf, Cursor pre-2.6,
// Zed, 5ire, Cline).
func stripUIResourceURIFromTools(tools []gomcp.Tool) []gomcp.Tool {
	if tools == nil {
		return nil
	}
	out := make([]gomcp.Tool, len(tools))
	for i, t := range tools {
		if t.Meta != nil && t.Meta.AdditionalFields != nil {
			if _, ok := t.Meta.AdditionalFields[uiMetaKey]; ok {
				newFields := make(map[string]any, len(t.Meta.AdditionalFields))
				for k, v := range t.Meta.AdditionalFields {
					if k == uiMetaKey {
						continue
					}
					newFields[k] = v
				}
				t.Meta = &gomcp.Meta{
					ProgressToken:    t.Meta.ProgressToken,
					AdditionalFields: newFields,
				}
			}
		}
		out[i] = t
	}
	return out
}

// ResourceMIMEType is the MIME type that signals MCP App hosts (claude.ai,
// ChatGPT, VS Code) to render the resource as an interactive iframe widget.
const ResourceMIMEType = "text/html;profile=mcp-app"

// dataPlaceholder is replaced with pre-injected JSON in widget HTML.
const dataPlaceholder = `"__INJECTED_DATA__"`

// cssPlaceholder is replaced with the contents of dashboard-base.css at serve
// time so that widget HTML files don't need to duplicate the common variables
// and reset styles inline.
const cssPlaceholder = "/*__INJECTED_CSS__*/"

// appResource defines a UI resource served as an MCP App widget.
type appResource struct {
	URI          string
	Name         string
	TemplateFile string // *_app.html widget file
	// DataFunc returns JSON-serializable data to inject as window.__DATA__.
	// Receives the authenticated email. Returns nil if unauthenticated.
	DataFunc func(manager *kc.Manager, auditStore *audit.Store, email string) any
}

// appResources lists the widget pages exposed as MCP App resources.
// Each uses a dedicated *_app.html optimized for iframe rendering
// (no external deps, AppBridge communication, pre-injected data).
var appResources = []appResource{
	{
		URI: "ui://kite-mcp/portfolio", Name: "Portfolio Widget",
		TemplateFile: "portfolio_app.html",
		DataFunc:     portfolioData,
	},
	{
		URI: "ui://kite-mcp/activity", Name: "Activity Widget",
		TemplateFile: "activity_app.html",
		DataFunc:     activityData,
	},
	{
		URI: "ui://kite-mcp/orders", Name: "Orders Widget",
		TemplateFile: "orders_app.html",
		DataFunc:     ordersData,
	},
	{
		URI: "ui://kite-mcp/alerts", Name: "Alerts Widget",
		TemplateFile: "alerts_app.html",
		DataFunc:     alertsData,
	},
	{
		URI: "ui://kite-mcp/paper", Name: "Paper Trading Widget",
		TemplateFile: "paper_app.html",
		DataFunc:     paperData,
	},
	{
		URI: "ui://kite-mcp/safety", Name: "Safety Widget",
		TemplateFile: "safety_app.html",
		DataFunc:     safetyData,
	},
	{
		URI: "ui://kite-mcp/order-form", Name: "Order Form Widget",
		TemplateFile: "order_form_app.html",
		DataFunc:     orderFormData,
	},
	{
		URI: "ui://kite-mcp/watchlist", Name: "Watchlist Widget",
		TemplateFile: "watchlist_app.html",
		DataFunc:     watchlistData,
	},
	{
		URI: "ui://kite-mcp/hub", Name: "Hub Widget",
		TemplateFile: "hub_app.html",
		DataFunc:     hubData,
	},
	{
		URI: "ui://kite-mcp/options-chain", Name: "Options Chain Widget",
		TemplateFile: "options_chain_app.html",
		DataFunc:     optionsChainData,
	},
	{
		URI: "ui://kite-mcp/chart", Name: "Chart Widget",
		TemplateFile: "chart_app.html",
		DataFunc:     chartData,
	},
	{
		URI: "ui://kite-mcp/setup", Name: "Setup Widget",
		TemplateFile: "setup_app.html",
		DataFunc:     setupData,
	},
	{
		URI: "ui://kite-mcp/credentials", Name: "Credentials Widget",
		TemplateFile: "credentials_app.html",
		DataFunc:     credentialsData,
	},
	{
		URI: "ui://kite-mcp/admin-overview", Name: "Admin Overview",
		TemplateFile: "admin_overview_app.html",
		DataFunc: func(manager *kc.Manager, auditStore *audit.Store, email string) any {
			if uStore := manager.UserStore(); uStore == nil || !uStore.IsAdmin(email) {
				return nil
			}
			resp := map[string]any{
				"active_sessions": manager.GetActiveSessionCount(),
				"uptime":          time.Since(serverStartTime).Truncate(time.Second).String(),
				"go_version":      runtime.Version(),
				"goroutines":      runtime.NumGoroutine(),
			}
			if uStore := manager.UserStore(); uStore != nil {
				resp["total_users"] = uStore.Count()
			}
			if rg := manager.RiskGuard(); rg != nil {
				resp["global_freeze"] = rg.GetGlobalFreezeStatus()
			}
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			resp["heap_alloc_mb"] = float64(memStats.HeapAlloc) / 1024 / 1024
			if memStats.NumGC > 0 {
				resp["gc_pause_ms"] = float64(memStats.PauseNs[(memStats.NumGC+255)%256]) / 1e6
			}
			return resp
		},
	},
	{
		URI: "ui://kite-mcp/admin-users", Name: "Admin Users",
		TemplateFile: "admin_users_app.html",
		DataFunc: func(manager *kc.Manager, auditStore *audit.Store, email string) any {
			if uStore := manager.UserStore(); uStore == nil || !uStore.IsAdmin(email) {
				return nil
			}
			users := manager.UserStore().List()
			type entry struct {
				Email       string `json:"email"`
				Role        string `json:"role"`
				Status      string `json:"status"`
				CreatedAt   string `json:"created_at"`
				LastLogin   string `json:"last_login,omitempty"`
				OnboardedBy string `json:"onboarded_by"`
			}
			entries := make([]entry, 0, len(users))
			for _, u := range users {
				var ll string
				if !u.LastLogin.IsZero() {
					ll = u.LastLogin.Format(time.RFC3339)
				}
				entries = append(entries, entry{
					Email: u.Email, Role: u.Role, Status: u.Status,
					CreatedAt: u.CreatedAt.Format(time.RFC3339), LastLogin: ll, OnboardedBy: u.OnboardedBy,
				})
			}
			return map[string]any{"total": len(users), "from": 0, "limit": len(users), "users": entries}
		},
	},
	{
		URI: "ui://kite-mcp/admin-metrics", Name: "Admin Metrics",
		TemplateFile: "admin_metrics_app.html",
		DataFunc: func(manager *kc.Manager, auditStore *audit.Store, email string) any {
			if uStore := manager.UserStore(); uStore == nil || !uStore.IsAdmin(email) {
				return nil
			}
			resp := map[string]any{"period": "24h", "active_sessions": manager.GetActiveSessionCount()}
			if auditStore != nil {
				since := time.Now().Add(-24 * time.Hour)
				if stats, err := auditStore.GetGlobalStats(since); err == nil {
					resp["total_calls"] = stats.TotalCalls
					resp["error_count"] = stats.ErrorCount
					resp["avg_latency_ms"] = stats.AvgLatencyMs
					if stats.TotalCalls > 0 {
						resp["error_rate"] = fmt.Sprintf("%.1f%%", float64(stats.ErrorCount)/float64(stats.TotalCalls)*100)
					} else {
						resp["error_rate"] = "0.0%"
					}
				}
				if metrics, err := auditStore.GetToolMetrics(since); err == nil {
					resp["tool_metrics"] = metrics
				}
			}
			var memStats runtime.MemStats
			runtime.ReadMemStats(&memStats)
			resp["heap_alloc_mb"] = float64(memStats.HeapAlloc) / 1024 / 1024
			resp["goroutines"] = runtime.NumGoroutine()
			return resp
		},
	},
	{
		URI: "ui://kite-mcp/admin-registry", Name: "Admin Registry",
		TemplateFile: "admin_registry_app.html",
		DataFunc: func(manager *kc.Manager, auditStore *audit.Store, email string) any {
			if uStore := manager.UserStore(); uStore == nil || !uStore.IsAdmin(email) {
				return nil
			}
			regStore := manager.RegistryStoreConcrete()
			if regStore == nil {
				return map[string]any{"total": 0, "active": 0, "registrations": []any{}}
			}
			regs := regStore.List()
			active := 0
			for _, r := range regs {
				if r.Status == "active" {
					active++
				}
			}
			return map[string]any{"total": len(regs), "active": active, "registrations": regs}
		},
	},
}

// pagePathToResourceURI maps dashboard URL paths to ui:// resource URIs.
var pagePathToResourceURI = map[string]string{
	"/dashboard":             "ui://kite-mcp/portfolio",
	"/dashboard/activity":    "ui://kite-mcp/activity",
	"/dashboard/orders":      "ui://kite-mcp/orders",
	"/dashboard/alerts":      "ui://kite-mcp/alerts",
	"/dashboard/paper":       "ui://kite-mcp/paper",
	"/dashboard/safety":      "ui://kite-mcp/safety",
	"/dashboard/order-form":  "ui://kite-mcp/order-form",
	"/dashboard/watchlist":   "ui://kite-mcp/watchlist",
	"/dashboard/hub":         "ui://kite-mcp/hub",
	"/dashboard/options":     "ui://kite-mcp/options-chain",
	"/dashboard/chart":       "ui://kite-mcp/chart",
	"/dashboard/setup":       "ui://kite-mcp/setup",
	"/dashboard/credentials": "ui://kite-mcp/credentials",
	"/admin/overview":        "ui://kite-mcp/admin-overview",
	"/admin/users":           "ui://kite-mcp/admin-users",
	"/admin/metrics":         "ui://kite-mcp/admin-metrics",
	"/admin/registry":        "ui://kite-mcp/admin-registry",
}

// withAppUI sets the flat _meta["ui/resourceUri"] key on a tool definition.
// Claude.ai only recognizes this flat format (not nested _meta.ui.resourceUri).
// The ext-apps SDK's getToolUiResourceUri() accepts both formats.
func withAppUI(t gomcp.Tool, resourceURI string) gomcp.Tool {
	if resourceURI == "" {
		return t
	}
	t.Meta = &gomcp.Meta{
		AdditionalFields: map[string]any{
			"ui/resourceUri": resourceURI,
		},
	}
	return t
}

// resourceURIForTool returns the ui:// resource URI for a tool based on its
// dashboard page mapping, or empty string if the tool has no associated page.
func resourceURIForTool(toolName string) string {
	pagePath, ok := toolDashboardPage[toolName]
	if !ok {
		return ""
	}
	return pagePathToResourceURI[pagePath]
}

// injectData replaces the dataPlaceholder in HTML with the JSON-encoded data.
// If data is nil, injects "null". Escapes "</script>" sequences in the JSON
// to prevent XSS breakout from the <script> tag context.
func injectData(html string, data any) string {
	var jsonStr string
	if data == nil {
		jsonStr = "null"
	} else {
		b, err := json.Marshal(data)
		if err != nil {
			jsonStr = "null"
		} else {
			jsonStr = string(b)
		}
	}
	// Defense-in-depth: Go's json.Marshal already escapes "<" as "\u003c",
	// so these replacements are no-ops in practice. They guard against future
	// changes to the JSON encoding (e.g., SetEscapeHTML(false)).
	jsonStr = strings.ReplaceAll(jsonStr, "</", `<\/`)
	jsonStr = strings.ReplaceAll(jsonStr, "<!--", `<\!--`)
	// U+2028 (LINE SEPARATOR) and U+2029 (PARAGRAPH SEPARATOR) are valid
	// whitespace in JSON but illegal line terminators inside JS string
	// literals. Go's json.Marshal does NOT escape them, so if attacker-
	// controlled data contains one, the injected JSON literal terminates
	// early in the browser and subsequent bytes execute as script — XSS.
	// Escape to their \uXXXX form so they live harmlessly inside the string.
	jsonStr = strings.ReplaceAll(jsonStr, "\u2028", `\u2028`)
	jsonStr = strings.ReplaceAll(jsonStr, "\u2029", `\u2029`)
	return strings.Replace(html, dataPlaceholder, jsonStr, 1)
}

// RegisterAppResources registers widget HTML pages as MCP App resources.
// Each resource handler dynamically injects user-specific data so widgets
// render instantly without needing AppBridge round-trips for initial load.
//
// It also installs an OnAfterListTools hook that strips the
// `_meta["ui/resourceUri"]` key from every tool in the list_tools response
// when the calling client does NOT advertise the MCP Apps UI extension.
// This keeps non-widget hosts (Claude Code, Windsurf, Cursor pre-2.6, Zed,
// 5ire, Cline) free of noisy fallback text while leaving widget-capable
// hosts (Claude.ai, Claude Desktop, ChatGPT, VS Code Copilot, Goose)
// untouched. Widget resource registration is NOT gated — clients that
// don't understand ui:// simply won't request them.
func RegisterAppResources(srv *server.MCPServer, manager *kc.Manager, auditStore *audit.Store, logger *slog.Logger) {
	// Install per-session UI capability gating on tool listings. We append
	// via GetHooks so this wiring lives with the other ext-apps code and
	// doesn't require touching the top-level server construction. Multiple
	// calls append additional hooks rather than replacing — mcp-go runs them
	// in registration order.
	if hooks := srv.GetHooks(); hooks != nil {
		hooks.AddAfterListTools(func(ctx context.Context, _ any, _ *gomcp.ListToolsRequest, result *gomcp.ListToolsResult) {
			if result == nil {
				return
			}
			var caps gomcp.ClientCapabilities
			if session := server.ClientSessionFromContext(ctx); session != nil {
				if ci, ok := session.(server.SessionWithClientInfo); ok {
					caps = ci.GetClientCapabilities()
				}
			}
			if clientSupportsUI(caps) {
				return
			}
			result.Tools = stripUIResourceURIFromTools(result.Tools)
		})
	}

	// Read the shared base CSS once so it can be injected into every widget
	// that contains the cssPlaceholder token.
	cssBytes, _ := templates.FS.ReadFile("dashboard-base.css")
	cssContent := string(cssBytes)

	registered := 0
	for _, res := range appResources {
		htmlBytes, err := templates.FS.ReadFile(res.TemplateFile)
		if err != nil {
			logger.Warn("Failed to read widget template",
				"uri", res.URI, "file", res.TemplateFile, "error", err)
			continue
		}
		htmlTemplate := string(htmlBytes)
		if cssContent != "" {
			htmlTemplate = strings.Replace(htmlTemplate, cssPlaceholder, cssContent, 1)
		}

		srv.AddResource(
			gomcp.Resource{
				URI:      res.URI,
				Name:     res.Name,
				MIMEType: ResourceMIMEType,
			},
			func(ctx context.Context, req gomcp.ReadResourceRequest) ([]gomcp.ResourceContents, error) {
				// Extract authenticated email from MCP session context.
				email := oauth.EmailFromContext(ctx)
				var data any
				if email != "" && res.DataFunc != nil {
					data = res.DataFunc(manager, auditStore, email)
				}

				html := injectData(htmlTemplate, data)

				return []gomcp.ResourceContents{
					gomcp.TextResourceContents{
						URI:      res.URI,
						MIMEType: ResourceMIMEType,
						Text:     html,
					},
				}, nil
			},
		)
		registered++
	}

	logger.Info("MCP App widget resources registered", "count", registered)
}

// --- Data functions for each widget ---

// Widget DataFuncs below take auditStore as an explicit parameter from
// RegisterAppResources (see line 289) rather than reading it off the
// Manager. This is a test-isolation requirement — widget tests use a
// locally-constructed audit store that isn't attached to the Manager.
//
// The path-to-100 escape-hatch research flagged these four call sites
// as "direct usecase calls that should go through the bus". They
// intentionally don't: the bus handler would have to resolve the audit
// store from the Manager, which breaks the test contract. Documented
// here instead of silently leaving them as mismatched escapes.

// portfolioData fetches holdings + positions via the portfolio widget use case.
func portfolioData(manager *kc.Manager, _ *audit.Store, email string) any {
	uc := usecases.NewGetPortfolioForWidgetUseCase(manager.SessionSvc(), manager.Logger)
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: email})
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	return result
}

// activityData fetches recent audit trail entries via the activity widget use case.
func activityData(_ *kc.Manager, auditStore *audit.Store, email string) any {
	if auditStore == nil {
		return nil
	}
	uc := usecases.NewGetActivityForWidgetUseCase(auditStore, slog.Default())
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: email})
	if err != nil {
		return nil
	}
	return result
}

// ordersData fetches recent order entries via the orders widget use case.
func ordersData(manager *kc.Manager, auditStore *audit.Store, email string) any {
	if auditStore == nil {
		return nil
	}
	uc := usecases.NewGetOrdersForWidgetUseCase(manager.SessionSvc(), auditStore, manager.Logger)
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: email})
	if err != nil {
		return nil
	}
	return result
}

// alertsData fetches active/triggered alerts via the alerts widget use case.
func alertsData(manager *kc.Manager, _ *audit.Store, email string) any {
	if manager.AlertStore() == nil {
		return nil
	}
	uc := usecases.NewGetAlertsForWidgetUseCase(manager.SessionSvc(), manager.AlertStore(), manager.Logger)
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: email})
	if err != nil {
		return nil
	}
	return result
}

// paperData fetches paper trading status, holdings, and positions for the widget.
func paperData(manager *kc.Manager, _ *audit.Store, email string) any {
	engine := manager.PaperEngine()
	if engine == nil {
		return map[string]any{"status": map[string]any{"enabled": false, "message": "Paper trading engine not configured."}}
	}

	status, err := engine.Status(email)
	if err != nil {
		return map[string]any{"error": "Failed to get paper status: " + err.Error()}
	}

	enabled, _ := status["enabled"].(bool)
	if !enabled {
		return map[string]any{"status": status}
	}

	// Fetch holdings and positions in parallel.
	var holdings, positions any
	var holdingsErr, positionsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); holdings, holdingsErr = engine.GetHoldings(email) }()
	go func() {
		defer wg.Done()
		posResult, err := engine.GetPositions(email)
		if err != nil {
			positionsErr = err
			return
		}
		// GetPositions returns map[string]any{"net":..., "day":...}; extract net.
		if posMap, ok := posResult.(map[string]any); ok {
			if net, ok := posMap["net"]; ok {
				positions = net
			} else {
				positions = posResult
			}
		} else {
			positions = posResult
		}
	}()
	wg.Wait()

	if holdingsErr != nil {
		return map[string]any{"error": "Failed to get paper holdings: " + holdingsErr.Error()}
	}
	if positionsErr != nil {
		return map[string]any{"error": "Failed to get paper positions: " + positionsErr.Error()}
	}

	return map[string]any{
		"status":    status,
		"holdings":  holdings,
		"positions": positions,
	}
}

// safetyData fetches riskguard status and limits for the safety widget.
func safetyData(manager *kc.Manager, auditStore *audit.Store, email string) any {
	guard := manager.RiskGuard()
	if guard == nil {
		return map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		}
	}

	status := guard.GetUserStatus(email)
	limits := guard.GetEffectiveLimits(email)

	_, hasToken := manager.TokenStore().Get(email)
	_, hasCreds := manager.CredentialStore().Get(email)

	return map[string]any{
		"enabled": true,
		"status":  status,
		"limits": map[string]any{
			"max_single_order_inr":  limits.MaxSingleOrderINR,
			"max_orders_per_day":    limits.MaxOrdersPerDay,
			"max_orders_per_minute": limits.MaxOrdersPerMinute,
			"duplicate_window_secs": limits.DuplicateWindowSecs,
			"max_daily_value_inr":   limits.MaxDailyValueINR,
			"auto_freeze_on_limit":  limits.AutoFreezeOnLimitHit,
		},
		"sebi": map[string]any{
			"static_egress_ip": true,
			"session_active":   hasToken,
			"credentials_set":  hasCreds,
			"order_tagging":    true,
			"audit_trail":      auditStore != nil,
		},
	}
}

// orderFormData returns paper-mode status for the order form widget.
// Margins are fetched dynamically via callServerTool('order_risk_report')
// rather than pre-injected, since the form needs fresh data at submission time.
func orderFormData(manager *kc.Manager, _ *audit.Store, email string) any {
	paperMode := false
	if engine := manager.PaperEngine(); engine != nil {
		paperMode = engine.IsEnabled(email)
	}
	return map[string]any{
		"paper_mode": paperMode,
	}
}

// watchlistData fetches all watchlists with items and LTP for the watchlist widget.
func watchlistData(manager *kc.Manager, _ *audit.Store, email string) any {
	store := manager.WatchlistStore()
	if store == nil {
		return nil
	}

	watchlists := store.ListWatchlists(email)
	if len(watchlists) == 0 {
		return map[string]any{"watchlists": []any{}, "total_count": 0}
	}

	// Sort by sort_order for consistent tab order.
	sort.Slice(watchlists, func(i, j int) bool {
		return watchlists[i].SortOrder < watchlists[j].SortOrder
	})

	// Collect all instruments across all watchlists for batch LTP.
	type itemWithLTP struct {
		Exchange         string  `json:"exchange"`
		Tradingsymbol    string  `json:"tradingsymbol"`
		Notes            string  `json:"notes,omitempty"`
		TargetEntry      float64 `json:"target_entry,omitempty"`
		TargetExit       float64 `json:"target_exit,omitempty"`
		LTP              float64 `json:"ltp,omitempty"`
		DistanceEntryPct float64 `json:"distance_entry_pct,omitempty"`
		DistanceExitPct  float64 `json:"distance_exit_pct,omitempty"`
		NearTarget       bool    `json:"near_target,omitempty"`
	}

	// Build per-watchlist item lists and collect instrument IDs.
	type wlEntry struct {
		ID    string        `json:"id"`
		Name  string        `json:"name"`
		Items []itemWithLTP `json:"items"`
	}

	entries := make([]wlEntry, 0, len(watchlists))
	var allInstruments []string
	instrumentSet := make(map[string]bool)

	for _, wl := range watchlists {
		items := store.GetItems(wl.ID)
		entry := wlEntry{ID: wl.ID, Name: wl.Name, Items: make([]itemWithLTP, 0, len(items))}
		for _, item := range items {
			entry.Items = append(entry.Items, itemWithLTP{
				Exchange:      item.Exchange,
				Tradingsymbol: item.Tradingsymbol,
				Notes:         item.Notes,
				TargetEntry:   item.TargetEntry,
				TargetExit:    item.TargetExit,
			})
			inst := item.Exchange + ":" + item.Tradingsymbol
			if !instrumentSet[inst] {
				instrumentSet[inst] = true
				allInstruments = append(allInstruments, inst)
			}
		}
		entries = append(entries, entry)
	}

	// Batch LTP fetch (max 50 per call, same pattern as alertsData).
	ltpMap := make(map[string]float64)
	client := brokerClientForEmail(manager, email)
	if client != nil && len(allInstruments) > 0 {
		const batchSize = 50
		for i := 0; i < len(allInstruments); i += batchSize {
			end := min(i+batchSize, len(allInstruments))
			batch := allInstruments[i:end]
			ltps, err := RetryBrokerCall(func() (map[string]broker.LTP, error) {
				return client.GetLTP(batch...)
			}, 2)
			if err == nil {
				for k, v := range ltps {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	// Enrich items with LTP and distance calculations.
	totalCount := 0
	for ei := range entries {
		for ii := range entries[ei].Items {
			item := &entries[ei].Items[ii]
			inst := item.Exchange + ":" + item.Tradingsymbol
			if ltp, ok := ltpMap[inst]; ok && ltp > 0 {
				item.LTP = ltp
				if item.TargetEntry > 0 {
					pct := ((ltp - item.TargetEntry) / item.TargetEntry) * 100
					item.DistanceEntryPct = pct
					if math.Abs(pct) <= 5.0 {
						item.NearTarget = true
					}
				}
				if item.TargetExit > 0 {
					pct := ((ltp - item.TargetExit) / item.TargetExit) * 100
					item.DistanceExitPct = pct
					if math.Abs(pct) <= 5.0 {
						item.NearTarget = true
					}
				}
			}
			totalCount++
		}
	}

	return map[string]any{
		"watchlists":  entries,
		"total_count": totalCount,
	}
}

// hubData returns account status, quick stats, and external URL for the hub widget.
func hubData(manager *kc.Manager, auditStore *audit.Store, email string) any {
	_, hasCreds := manager.CredentialStore().Get(email)

	kiteConnected := false
	if entry, ok := manager.TokenStore().Get(email); ok {
		kiteConnected = !kc.IsKiteTokenExpired(entry.StoredAt)
	}

	paperOn := false
	if engine := manager.PaperEngine(); engine != nil {
		paperOn = engine.IsEnabled(email)
	}

	alertCount := 0
	if manager.AlertStore() != nil {
		for _, a := range manager.AlertStore().List(email) {
			if !a.Triggered {
				alertCount++
			}
		}
	}

	toolCallsToday := 0
	if auditStore != nil {
		since := time.Now().Truncate(24 * time.Hour)
		if stats, err := auditStore.GetStats(email, since, "", false); err == nil {
			toolCallsToday = stats.TotalCalls
		}
	}

	externalURL := manager.ExternalURL()
	if externalURL == "" {
		externalURL = "https://kite-mcp-server.fly.dev"
	}

	return map[string]any{
		"email":            email,
		"kite_connected":   kiteConnected,
		"credentials_set":  hasCreds,
		"paper_mode":       paperOn,
		"active_alerts":    alertCount,
		"tool_calls_today": toolCallsToday,
		"external_url":     externalURL,
	}
}

// optionsChainData returns nil because the options chain widget boots into an
// idle state. The user picks the underlying interactively and loads data via
// AppBridge calls to get_option_chain / options_greeks.
func optionsChainData(manager *kc.Manager, _ *audit.Store, email string) any {
	return nil
}

// chartData returns nil because the chart widget boots into an idle state.
// The user picks the symbol interactively and loads data via AppBridge calls
// to search_instruments, get_historical_data, and technical_indicators.
func chartData(_ *kc.Manager, _ *audit.Store, _ string) any {
	return nil
}

// setupData returns onboarding state for the setup checklist widget.
// Step 1 (credentials registered) is hydrated from the credential store.
// Step 2 (IP whitelisted) can't be verified independently — it's confirmed
// indirectly when Step 3 (test_ip_whitelist tool) passes. Until then the
// widget shows Step 2 as unverified.
func setupData(manager *kc.Manager, _ *audit.Store, email string) any {
	credsRegistered := false
	apiKeyMasked := ""
	if store := manager.CredentialStore(); store != nil {
		if entry, ok := store.Get(email); ok {
			credsRegistered = true
			apiKeyMasked = maskAPIKey(entry.APIKey)
		}
	}
	return map[string]any{
		"egress_ip":              setupStaticEgressIP,
		"credentials_registered": credsRegistered,
		"api_key_masked":         apiKeyMasked,
		// ready_to_trade currently mirrors credentials_registered — Step 3
		// connectivity result lives in the browser, not server-side state.
		"ready_to_trade": credsRegistered,
	}
}

// maskAPIKey returns a masked form of a Kite API key: first 3 chars, stars,
// last 3 chars, e.g. "4c0****...3b7". Returns empty string for short/empty input.
func maskAPIKey(apiKey string) string {
	if len(apiKey) < 7 {
		return ""
	}
	return apiKey[:3] + "****..." + apiKey[len(apiKey)-3:]
}

// credentialsData returns current credential metadata for the rotation widget.
// Only the API key is surfaced (masked) — the secret is never read back into
// the widget. last_updated comes from KiteCredentialEntry.StoredAt which is
// set on every Set() call in the credential store.
func credentialsData(manager *kc.Manager, _ *audit.Store, email string) any {
	resp := map[string]any{
		"credentials_registered": false,
		"api_key_masked":         "",
		"last_updated":           "",
	}
	store := manager.CredentialStore()
	if store == nil {
		return resp
	}
	entry, ok := store.Get(email)
	if !ok {
		return resp
	}
	resp["credentials_registered"] = true
	resp["api_key_masked"] = maskAPIKey(entry.APIKey)
	if !entry.StoredAt.IsZero() {
		resp["last_updated"] = entry.StoredAt.Format(time.RFC3339)
	}
	return resp
}

// brokerClientForEmail resolves a broker.Client for the given email,
// or nil if credentials/token are not available.
func brokerClientForEmail(manager *kc.Manager, email string) broker.Client {
	client, err := manager.SessionSvc().GetBrokerForEmail(email)
	if err != nil {
		return nil
	}
	return client
}
