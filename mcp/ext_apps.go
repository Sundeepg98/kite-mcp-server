package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"math"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ResourceMIMEType is the MIME type that signals MCP App hosts (claude.ai,
// ChatGPT, VS Code) to render the resource as an interactive iframe widget.
const ResourceMIMEType = "text/html;profile=mcp-app"

// dataPlaceholder is replaced with pre-injected JSON in widget HTML.
const dataPlaceholder = `"__INJECTED_DATA__"`

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
}

// pagePathToResourceURI maps dashboard URL paths to ui:// resource URIs.
var pagePathToResourceURI = map[string]string{
	"/dashboard":          "ui://kite-mcp/portfolio",
	"/dashboard/activity": "ui://kite-mcp/activity",
	"/dashboard/orders":   "ui://kite-mcp/orders",
	"/dashboard/alerts":   "ui://kite-mcp/alerts",
	"/dashboard/paper":    "ui://kite-mcp/paper",
	"/dashboard/safety":      "ui://kite-mcp/safety",
	"/dashboard/order-form": "ui://kite-mcp/order-form",
	"/dashboard/watchlist":  "ui://kite-mcp/watchlist",
	"/dashboard/hub":       "ui://kite-mcp/hub",
	"/dashboard/options":   "ui://kite-mcp/options-chain",
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
	return strings.Replace(html, dataPlaceholder, jsonStr, 1)
}

// RegisterAppResources registers widget HTML pages as MCP App resources.
// Each resource handler dynamically injects user-specific data so widgets
// render instantly without needing AppBridge round-trips for initial load.
func RegisterAppResources(srv *server.MCPServer, manager *kc.Manager, auditStore *audit.Store, logger *slog.Logger) {
	registered := 0
	for _, res := range appResources {
		res := res

		htmlBytes, err := templates.FS.ReadFile(res.TemplateFile)
		if err != nil {
			logger.Warn("Failed to read widget template",
				"uri", res.URI, "file", res.TemplateFile, "error", err)
			continue
		}
		htmlTemplate := string(htmlBytes)

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

// portfolioData fetches holdings + positions in parallel for the portfolio widget.
func portfolioData(manager *kc.Manager, _ *audit.Store, email string) any {
	client := kiteClientForEmail(manager, email)
	if client == nil {
		return nil
	}

	// Parallel API calls to reduce latency.
	var holdings kiteconnect.Holdings
	var positions kiteconnect.Positions
	var holdingsErr, positionsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); holdings, holdingsErr = client.GetHoldings() }()
	go func() { defer wg.Done(); positions, positionsErr = client.GetPositions() }()
	wg.Wait()

	if holdingsErr != nil {
		return map[string]string{"error": "Failed to fetch holdings: " + holdingsErr.Error()}
	}
	if positionsErr != nil {
		return map[string]string{"error": "Failed to fetch positions: " + positionsErr.Error()}
	}

	type holdingItem struct {
		Symbol     string  `json:"tradingsymbol"`
		Exchange   string  `json:"exchange"`
		Quantity   int     `json:"quantity"`
		AvgPrice   float64 `json:"average_price"`
		LastPrice  float64 `json:"last_price"`
		PnL        float64 `json:"pnl"`
		DayChgPct  float64 `json:"day_change_percentage"`
	}
	type posItem struct {
		Symbol   string  `json:"tradingsymbol"`
		Exchange string  `json:"exchange"`
		Quantity int     `json:"quantity"`
		AvgPrice float64 `json:"average_price"`
		LastPrice float64 `json:"last_price"`
		PnL      float64 `json:"pnl"`
		Product  string  `json:"product"`
	}

	hItems := make([]holdingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		hItems = append(hItems, holdingItem{
			Symbol: h.Tradingsymbol, Exchange: h.Exchange, Quantity: h.Quantity,
			AvgPrice: h.AveragePrice, LastPrice: h.LastPrice, PnL: h.PnL,
			DayChgPct: h.DayChangePercentage,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		totalPnL += h.PnL
	}

	pItems := make([]posItem, 0, len(positions.Net))
	var posPnL float64
	for _, p := range positions.Net {
		pItems = append(pItems, posItem{
			Symbol: p.Tradingsymbol, Exchange: p.Exchange, Quantity: p.Quantity,
			AvgPrice: p.AveragePrice, LastPrice: p.LastPrice, PnL: p.PnL,
			Product: p.Product,
		})
		posPnL += p.PnL
	}

	return map[string]any{
		"holdings":  hItems,
		"positions": pItems,
		"summary": map[string]any{
			"holdings_count":  len(holdings),
			"total_invested":  totalInvested,
			"total_current":   totalCurrent,
			"total_pnl":       totalPnL,
			"positions_count": len(positions.Net),
			"positions_pnl":   posPnL,
		},
	}
}

// activityData fetches recent audit trail entries for the activity widget.
func activityData(_ *kc.Manager, auditStore *audit.Store, email string) any {
	if auditStore == nil {
		return nil
	}

	since := time.Now().AddDate(0, 0, -7)
	entries, _, err := auditStore.List(email, audit.ListOptions{
		Limit: 20,
		Since: since,
	})
	if err != nil {
		return nil
	}

	stats, _ := auditStore.GetStats(email, since)
	toolCounts, _ := auditStore.GetToolCounts(email, since)

	return map[string]any{
		"entries":     entries,
		"stats":       stats,
		"tool_counts": toolCounts,
	}
}

// ordersData fetches recent order entries for the orders widget.
func ordersData(manager *kc.Manager, auditStore *audit.Store, email string) any {
	if auditStore == nil {
		return nil
	}

	since := time.Now().AddDate(0, 0, -1) // today
	toolCalls, err := auditStore.ListOrders(email, since)
	if err != nil {
		return nil
	}

	client := kiteClientForEmail(manager, email)

	type orderEntry struct {
		OrderID        string  `json:"order_id"`
		Symbol         string  `json:"tradingsymbol"`
		Exchange       string  `json:"exchange"`
		Side           string  `json:"transaction_type"`
		OrderType      string  `json:"order_type"`
		Quantity       float64 `json:"quantity"`
		FilledQuantity float64 `json:"filled_quantity"`
		Price          float64 `json:"price"`
		AveragePrice   float64 `json:"average_price"`
		Status         string  `json:"status"`
		PlacedAt       string  `json:"placed_at"`
	}

	// Fetch all orders in a single API call (instead of N GetOrderHistory calls).
	orderStatusMap := make(map[string]kiteconnect.Order)
	if client != nil {
		if allOrders, oErr := client.GetOrders(); oErr == nil {
			for _, o := range allOrders {
				orderStatusMap[o.OrderID] = o
			}
		}
	}

	orders := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		oe := orderEntry{OrderID: tc.OrderID, PlacedAt: tc.StartedAt.Format(time.RFC3339)}
		if tc.InputParams != "" {
			var params map[string]any
			if json.Unmarshal([]byte(tc.InputParams), &params) == nil {
				if v, ok := params["tradingsymbol"].(string); ok { oe.Symbol = v }
				if v, ok := params["exchange"].(string); ok { oe.Exchange = v }
				if v, ok := params["transaction_type"].(string); ok { oe.Side = v }
				if v, ok := params["order_type"].(string); ok { oe.OrderType = v }
				if v, ok := params["quantity"].(float64); ok { oe.Quantity = v }
				if v, ok := params["price"].(float64); ok { oe.Price = v }
			}
		}
		// Enrich from the single GetOrders() result.
		if o, ok := orderStatusMap[oe.OrderID]; ok {
			oe.Status = o.Status
			oe.FilledQuantity = float64(o.FilledQuantity)
			oe.AveragePrice = o.AveragePrice
			if oe.Symbol == "" { oe.Symbol = o.TradingSymbol }
			if oe.Exchange == "" { oe.Exchange = o.Exchange }
			if oe.Side == "" { oe.Side = o.TransactionType }
			if oe.Quantity == 0 { oe.Quantity = float64(o.Quantity) }
			if oe.Price == 0 { oe.Price = o.Price }
		}
		orders = append(orders, oe)
	}

	var completed, pending, rejected int
	var totalBuyVal, totalSellVal float64
	for _, o := range orders {
		switch o.Status {
		case "COMPLETE":
			completed++
			val := o.AveragePrice * o.FilledQuantity
			if o.Side == "BUY" { totalBuyVal += val } else { totalSellVal += val }
		case "OPEN", "TRIGGER PENDING", "VALIDATION PENDING":
			pending++
		case "REJECTED", "CANCELLED":
			rejected++
		}
	}

	return map[string]any{
		"orders": orders,
		"summary": map[string]any{
			"total": len(orders), "completed": completed,
			"pending": pending, "rejected": rejected,
			"total_buy_value": totalBuyVal, "total_sell_value": totalSellVal,
		},
	}
}

// alertsData fetches active/triggered alerts for the alerts widget.
func alertsData(manager *kc.Manager, _ *audit.Store, email string) any {
	if manager.AlertStore() == nil {
		return nil
	}
	allAlerts := manager.AlertStore().List(email)
	client := kiteClientForEmail(manager, email)

	type alertItem struct {
		ID          string  `json:"id"`
		Symbol      string  `json:"tradingsymbol"`
		Exchange    string  `json:"exchange"`
		Direction   string  `json:"direction"`
		TargetPrice float64 `json:"target_price"`
		CurrentPrice float64 `json:"current_price,omitempty"`
		DistancePct  float64 `json:"distance_pct,omitempty"`
		CreatedAt   string  `json:"created_at"`
		TriggeredAt string  `json:"triggered_at,omitempty"`
		TriggeredPrice float64 `json:"triggered_price,omitempty"`
	}

	active := make([]alertItem, 0)
	triggered := make([]alertItem, 0)

	// Batch LTP lookup for active alerts
	ltpMap := make(map[string]float64)
	if client != nil {
		instruments := make([]string, 0)
		for _, a := range allAlerts {
			if !a.Triggered {
				inst := a.Exchange + ":" + a.Tradingsymbol
				instruments = append(instruments, inst)
			}
		}
		if len(instruments) > 0 {
			if ltps, err := client.GetLTP(instruments...); err == nil {
				for k, v := range ltps {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	for _, a := range allAlerts {
		item := alertItem{
			ID: a.ID, Symbol: a.Tradingsymbol, Exchange: a.Exchange,
			Direction: string(a.Direction), TargetPrice: a.TargetPrice,
			CreatedAt: a.CreatedAt.Format(time.RFC3339),
		}
		if a.Triggered {
			item.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
			item.TriggeredPrice = a.TriggeredPrice
			triggered = append(triggered, item)
		} else {
			inst := a.Exchange + ":" + a.Tradingsymbol
			if ltp, ok := ltpMap[inst]; ok {
				item.CurrentPrice = ltp
				if ltp > 0 {
					item.DistancePct = (a.TargetPrice - ltp) / ltp * 100
				}
			}
			active = append(active, item)
		}
	}

	return map[string]any{
		"active":          active,
		"triggered":       triggered,
		"active_count":    len(active),
		"triggered_count": len(triggered),
	}
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
// Margins are fetched dynamically via callServerTool('pre_trade_check')
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
		Exchange        string  `json:"exchange"`
		Tradingsymbol   string  `json:"tradingsymbol"`
		Notes           string  `json:"notes,omitempty"`
		TargetEntry     float64 `json:"target_entry,omitempty"`
		TargetExit      float64 `json:"target_exit,omitempty"`
		LTP             float64 `json:"ltp,omitempty"`
		DistanceEntryPct float64 `json:"distance_entry_pct,omitempty"`
		DistanceExitPct  float64 `json:"distance_exit_pct,omitempty"`
		NearTarget      bool    `json:"near_target,omitempty"`
	}

	// Build per-watchlist item lists and collect instrument IDs.
	type wlEntry struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
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
	client := kiteClientForEmail(manager, email)
	if client != nil && len(allInstruments) > 0 {
		const batchSize = 50
		for i := 0; i < len(allInstruments); i += batchSize {
			end := i + batchSize
			if end > len(allInstruments) {
				end = len(allInstruments)
			}
			batch := allInstruments[i:end]
			if ltps, err := client.GetLTP(batch...); err == nil {
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
		if stats, err := auditStore.GetStats(email, since); err == nil {
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

// kiteClientForEmail creates a kiteconnect.Client for the given email,
// or nil if credentials/token are not available.
func kiteClientForEmail(manager *kc.Manager, email string) *kiteconnect.Client {
	credEntry, hasCreds := manager.CredentialStore().Get(email)
	tokenEntry, hasToken := manager.TokenStore().Get(email)
	if !hasCreds || !hasToken {
		return nil
	}
	client := kiteconnect.New(credEntry.APIKey)
	client.SetAccessToken(tokenEntry.AccessToken)
	return client
}
