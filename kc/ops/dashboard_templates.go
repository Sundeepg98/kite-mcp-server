package ops

import (
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ============================================================================
// Page data types for server-side template rendering
// ============================================================================

// PortfolioPageData is the top-level data for the dashboard (portfolio) page template.
type PortfolioPageData struct {
	Email       string
	Role        string
	TokenValid  bool
	UpdatedAt   string
	Stats       PortfolioStatsData
	Market      MarketBarData
	Holdings    PortfolioHoldingsData
	Positions   PortfolioPositionsData
	AlertCount  int
	Credentials        credentialStatus
	Expired            bool // true when kite token is expired
	HasKiteCredentials bool // true when user has stored Kite API credentials
	DevMode            bool // true when server is running with mock broker
}

// ActivityPageData is the top-level data for the activity page template.
type ActivityPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      ActivityStatsData
	Timeline   ActivityTimelineData
}

// OrdersPageData is the top-level data for the orders page template.
type OrdersPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      OrdersStatsData
	Orders     OrdersTableData
}

// AlertsPageData is the top-level data for the alerts page template.
type AlertsPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Stats      AlertsStatsData
	Active     AlertsActiveData
	Triggered  AlertsTriggeredData
}

// PaperPageData is the top-level data for the paper trading page template.
type PaperPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Banner     PaperBannerData
	Stats      PaperStatsData
	Tables     PaperTablesData
	Enabled    bool
}

// SafetyPageData is the top-level data for the safety page template.
type SafetyPageData struct {
	Email      string
	Role       string
	TokenValid bool
	UpdatedAt  string
	Freeze     SafetyFreezeData
	Limits     SafetyLimitsData
	SEBI       SafetySEBIData
}

// ============================================================================
// Template initialization
// ============================================================================

// InitTemplates parses all user dashboard page templates with their partials.
// Call this during DashboardHandler setup.
func (d *DashboardHandler) InitTemplates() {
	partials := []string{
		"user_portfolio_stats.html",
		"user_portfolio_holdings.html",
		"user_portfolio_positions.html",
		"user_market_bar.html",
		"user_activity_stats.html",
		"user_activity_timeline.html",
		"user_orders_stats.html",
		"user_orders_table.html",
		"user_alerts_stats.html",
		"user_alerts_active.html",
		"user_alerts_triggered.html",
		"user_paper_stats.html",
		"user_paper_banner.html",
		"user_paper_tables.html",
		"user_safety_freeze.html",
		"user_safety_limits.html",
		"user_safety_sebi.html",
	}

	parsePage := func(page string) *htmltemplate.Template {
		files := append([]string{page}, partials...)
		tmpl, err := htmltemplate.ParseFS(templates.FS, files...)
		if err != nil {
			d.logger.Error("Failed to parse user dashboard template", "page", page, "error", err)
			return nil
		}
		return tmpl
	}

	d.portfolioTmpl = parsePage("dashboard.html")
	d.activityTmpl = parsePage("activity.html")
	d.ordersTmpl = parsePage("orders.html")
	d.alertsTmpl = parsePage("alerts.html")
	d.paperTmpl = parsePage("paper.html")
	d.safetyTmpl = parsePage("safety.html")

	// Also parse fragment templates for htmx partial responses.
	fragTmpl, err := userDashboardFragmentTemplates()
	if err != nil {
		d.logger.Error("Failed to parse user fragment templates", "error", err)
	} else {
		d.fragmentTmpl = fragTmpl
	}
}

// ============================================================================
// Common helpers for page handlers
// ============================================================================

// userContext extracts email, role, and token validity from the request.
func (d *DashboardHandler) userContext(r *http.Request) (email, role string, tokenValid bool) {
	email = oauth.EmailFromContext(r.Context())
	if email == "" {
		return "", "", false
	}
	role = "trader"
	if d.adminCheck != nil && d.adminCheck(email) {
		role = "admin"
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	tokenValid = hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
	return
}

// nowTimestamp returns the current time formatted for the "Updated" display.
func nowTimestamp() string {
	return time.Now().Format("Updated 15:04:05")
}

// ============================================================================
// Portfolio page: server-side rendering
// ============================================================================

func (d *DashboardHandler) servePortfolioPage(w http.ResponseWriter, r *http.Request) {
	if d.portfolioTmpl == nil {
		d.servePageFallback(w, "dashboard.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := PortfolioPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
		Expired:    !tokenValid,
		DevMode:    d.manager.DevMode(),
	}

	// Fetch status for stat cards
	statusResp := d.buildUserStatus(email)

	// Fetch alerts count
	alertCount := 0
	if email != "" {
		allAlerts := d.manager.AlertStore().List(email)
		for _, a := range allAlerts {
			if !a.Triggered {
				alertCount++
			}
		}
	}

	// Fetch portfolio data (may fail if token expired)
	var portfolio portfolioResponse
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

			holdings, holdingsErr := client.GetHoldings()
			positions, positionsErr := client.GetPositions()

			if holdingsErr == nil && positionsErr == nil {
				portfolio = d.buildPortfolioResponse(holdings, positions)
			} else {
				if holdingsErr != nil {
					d.logger.Error("Failed to fetch holdings for SSR", "email", email, "error", holdingsErr)
				}
				if positionsErr != nil {
					d.logger.Error("Failed to fetch positions for SSR", "email", email, "error", positionsErr)
				}
			}
		}
	}

	data.Stats = portfolioToStatsData(statusResp, portfolio, alertCount)
	data.Holdings = portfolioToHoldingsData(portfolio.Holdings)
	data.Positions = portfolioToPositionsData(portfolio.Positions)

	// Market indices (may fail if token expired)
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
			ohlcData, err := client.GetOHLC("NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX")
			if err == nil {
				indices := make(map[string]any, len(ohlcData))
				for k, v := range ohlcData {
					change := v.LastPrice - v.OHLC.Close
					changePct := 0.0
					if v.OHLC.Close > 0 {
						changePct = (change / v.OHLC.Close) * 100
					}
					indices[k] = map[string]any{
						"last_price": v.LastPrice,
						"change":     math.Round(change*100) / 100,
						"change_pct": math.Round(changePct*100) / 100,
					}
				}
				data.Market = marketIndicesToBarData(indices)
			}
		}
	}
	// Ensure market bar has fallback data
	if len(data.Market.Indices) == 0 {
		data.Market = MarketBarData{
			Indices: []MarketIndex{
				{Label: "NIFTY 50", PriceFmt: "--", ChangeFmt: "--"},
				{Label: "BANK NIFTY", PriceFmt: "--", ChangeFmt: "--"},
				{Label: "SENSEX", PriceFmt: "--", ChangeFmt: "--"},
			},
		}
	}

	// Credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		data.Credentials = credentialStatus{Stored: true, APIKey: credEntry.APIKey}
	}
	data.HasKiteCredentials = hasCreds

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.portfolioTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render portfolio page", "error", err)
	}
}

// buildUserStatus builds a statusResponse for the given email (used in SSR).
func (d *DashboardHandler) buildUserStatus(email string) statusResponse {
	resp := statusResponse{Email: email}
	if d.adminCheck != nil && d.adminCheck(email) {
		resp.Role = "admin"
		resp.IsAdmin = true
	} else {
		resp.Role = "trader"
	}

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format(time.RFC3339),
		}
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{Stored: true, APIKey: credEntry.APIKey}
	}

	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err == nil {
		resp.Ticker = tickerStatus{Running: tickerSt.Running, Subscriptions: len(tickerSt.Subscriptions)}
	}

	return resp
}

// ============================================================================
// Activity page: server-side rendering
// ============================================================================

func (d *DashboardHandler) serveActivityPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.activityTmpl == nil {
		d.servePageFallback(w, "activity.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := ActivityPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	// Fetch initial activity data (today)
	if d.auditStore != nil && email != "" {
		today := time.Now().Truncate(24 * time.Hour)
		opts := audit.ListOptions{
			Limit: 50,
			Since: today,
		}
		ptrEntries, _, _ := d.auditStore.List(email, opts)
		stats, _ := d.auditStore.GetStats(email, today, "", false)

		// Convert []*ToolCall to []ToolCall for the converter function.
		entries := make([]audit.ToolCall, 0, len(ptrEntries))
		for _, e := range ptrEntries {
			if e != nil {
				entries = append(entries, *e)
			}
		}

		data.Stats = activityToStatsData(stats)
		data.Timeline = activityToTimelineData(entries)
	} else {
		data.Stats = activityToStatsData(nil)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.activityTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render activity page", "error", err)
	}
}

// ============================================================================
// Orders page: server-side rendering
// ============================================================================

func (d *DashboardHandler) serveOrdersPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.ordersTmpl == nil {
		d.servePageFallback(w, "orders.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := OrdersPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	// Fetch orders from audit trail for today
	if d.auditStore != nil && email != "" {
		since := time.Now().Truncate(24 * time.Hour)
		toolCalls, _ := d.auditStore.ListOrders(email, since)
		entries := d.buildOrderEntries(toolCalls, email)
		summary := d.buildOrderSummary(entries)

		data.Stats = ordersToStatsData(summary)
		data.Orders = ordersToTableData(entries)
	} else {
		data.Stats = ordersToStatsData(ordersSummary{})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.ordersTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render orders page", "error", err)
	}
}

// buildOrderEntries constructs order entries from audit tool calls, optionally enriching with Kite API.
func (d *DashboardHandler) buildOrderEntries(toolCalls []*audit.ToolCall, email string) []orderEntry {
	entries := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		if tc == nil {
			continue
		}
		oe := orderEntry{
			OrderID:  tc.OrderID,
			PlacedAt: tc.StartedAt.Format(time.RFC3339),
		}
		parseOrderParamsJSON(tc.InputParams, &oe)
		entries = append(entries, oe)
	}

	// Try to enrich with Kite API
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt) {
		client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
		d.enrichOrdersWithKite(client, entries)
	}

	return entries
}

// enrichOrdersWithKite enriches order entries with fill details and current prices from Kite API.
func (d *DashboardHandler) enrichOrdersWithKite(client *kiteconnect.Client, entries []orderEntry) {
	type ltpKey struct {
		exchange string
		symbol   string
	}
	ltpKeys := make(map[string]ltpKey)

	for i := range entries {
		oe := &entries[i]
		history, histErr := client.GetOrderHistory(oe.OrderID)
		if histErr != nil {
			oe.Error = "order history: " + histErr.Error()
			continue
		}
		if len(history) > 0 {
			latest := history[len(history)-1]
			oe.Status = latest.Status
			if oe.Symbol == "" {
				oe.Symbol = latest.TradingSymbol
			}
			if oe.Exchange == "" {
				oe.Exchange = latest.Exchange
			}
			if oe.Side == "" {
				oe.Side = latest.TransactionType
			}
			if oe.OrderType == "" {
				oe.OrderType = latest.OrderType
			}
			if oe.Quantity == 0 {
				oe.Quantity = latest.Quantity
			}
			if latest.Status == "COMPLETE" && latest.AveragePrice > 0 {
				fp := latest.AveragePrice
				oe.FillPrice = &fp
				if latest.FilledQuantity > 0 {
					oe.Quantity = latest.FilledQuantity
				}
				if oe.Exchange != "" && oe.Symbol != "" {
					key := oe.Exchange + ":" + oe.Symbol
					ltpKeys[key] = ltpKey{exchange: oe.Exchange, symbol: oe.Symbol}
				}
			}
		}
	}

	if len(ltpKeys) > 0 {
		instruments := make([]string, 0, len(ltpKeys))
		for k := range ltpKeys {
			instruments = append(instruments, k)
		}
		ltpMap, ltpErr := client.GetLTP(instruments...)
		if ltpErr != nil {
			return
		}
		for i := range entries {
			oe := &entries[i]
			if oe.FillPrice == nil || oe.Exchange == "" || oe.Symbol == "" {
				continue
			}
			key := oe.Exchange + ":" + oe.Symbol
			if quote, ok := ltpMap[key]; ok && quote.LastPrice > 0 {
				cp := quote.LastPrice
				oe.CurrentPrice = &cp
				dir := 1.0
				if oe.Side == "SELL" {
					dir = -1.0
				}
				pnl := (cp - *oe.FillPrice) * oe.Quantity * dir
				pnl = math.Round(pnl*100) / 100
				oe.PnL = &pnl
				if *oe.FillPrice > 0 {
					pnlPct := ((cp - *oe.FillPrice) / *oe.FillPrice) * 100 * dir
					pnlPct = math.Round(pnlPct*100) / 100
					oe.PnLPct = &pnlPct
				}
			}
		}
	}
}

// buildOrderSummary computes order summary from entries.
func (d *DashboardHandler) buildOrderSummary(entries []orderEntry) ordersSummary {
	summary := ordersSummary{TotalOrders: len(entries)}
	var totalPnL float64
	hasPnL := false
	for _, oe := range entries {
		if oe.Status == "COMPLETE" {
			summary.Completed++
		}
		if oe.PnL != nil {
			hasPnL = true
			totalPnL += *oe.PnL
			if *oe.PnL > 0 {
				summary.WinningTrades++
			} else if *oe.PnL < 0 {
				summary.LosingTrades++
			}
		}
	}
	if hasPnL {
		rounded := math.Round(totalPnL*100) / 100
		summary.TotalPnL = &rounded
	}
	return summary
}

// ============================================================================
// Alerts page: server-side rendering
// ============================================================================

func (d *DashboardHandler) serveAlertsPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.alertsTmpl == nil {
		d.servePageFallback(w, "alerts.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := AlertsPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	if email != "" {
		allAlerts := d.manager.AlertStore().List(email)
		var activeAlerts, triggeredAlerts []*alertCopy
		for _, a := range allAlerts {
			ac := &alertCopy{
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: string(a.Direction), TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, Triggered: a.Triggered,
				CreatedAt: a.CreatedAt, TriggeredAt: a.TriggeredAt,
				TriggeredPrice: a.TriggeredPrice, NotificationSentAt: a.NotificationSentAt,
			}
			if a.Triggered {
				triggeredAlerts = append(triggeredAlerts, ac)
			} else {
				activeAlerts = append(activeAlerts, ac)
			}
		}

		// LTP enrichment for active alerts
		ltpMap := make(map[string]float64)
		if tokenValid {
			credEntry, hasCreds := d.manager.CredentialStore().Get(email)
			tokenEntry, hasToken := d.manager.TokenStore().Get(email)
			if hasCreds && hasToken {
				client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
				instruments := make(map[string]bool)
				for _, a := range activeAlerts {
					key := a.Exchange + ":" + a.Tradingsymbol
					instruments[key] = true
				}
				if len(instruments) > 0 {
					instList := make([]string, 0, len(instruments))
					for k := range instruments {
						instList = append(instList, k)
					}
					ltpData, err := client.GetLTP(instList...)
					if err == nil {
						for k, v := range ltpData {
							if v.LastPrice > 0 {
								ltpMap[k] = v.LastPrice
							}
						}
					}
				}
			}
		}

		// Build enriched active alerts
		enrichedActive := make([]enrichedActiveAlert, 0, len(activeAlerts))
		for _, a := range activeAlerts {
			ea := enrichedActiveAlert{
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: a.Direction, TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, CreatedAt: a.CreatedAt.Format(time.RFC3339),
			}
			key := a.Exchange + ":" + a.Tradingsymbol
			if cp, ok := ltpMap[key]; ok {
				ea.CurrentPrice = cp
				if cp > 0 {
					dist := math.Round(math.Abs(cp-a.TargetPrice)/cp*10000) / 100
					ea.DistancePct = &dist
				}
			}
			enrichedActive = append(enrichedActive, ea)
		}

		// Build enriched triggered alerts
		enrichedTriggered := make([]enrichedTriggeredAlert, 0, len(triggeredAlerts))
		var totalTriggerDuration time.Duration
		triggerDurationCount := 0
		for _, a := range triggeredAlerts {
			et := enrichedTriggeredAlert{
				ID: a.ID, Tradingsymbol: a.Tradingsymbol, Exchange: a.Exchange,
				Direction: a.Direction, TargetPrice: a.TargetPrice,
				ReferencePrice: a.ReferencePrice, TriggeredPrice: a.TriggeredPrice,
				CreatedAt: a.CreatedAt.Format(time.RFC3339),
			}
			if !a.TriggeredAt.IsZero() {
				et.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
				ttd := a.TriggeredAt.Sub(a.CreatedAt)
				et.TimeToTrigger = formatDuration(ttd)
				totalTriggerDuration += ttd
				triggerDurationCount++
			}
			if !a.NotificationSentAt.IsZero() {
				et.NotificationSentAt = a.NotificationSentAt.Format(time.RFC3339)
				if !a.TriggeredAt.IsZero() {
					et.NotificationDelay = formatDuration(a.NotificationSentAt.Sub(a.TriggeredAt))
				}
			}
			enrichedTriggered = append(enrichedTriggered, et)
		}

		summary := alertsSummary{
			ActiveCount:    len(enrichedActive),
			TriggeredCount: len(enrichedTriggered),
		}
		if triggerDurationCount > 0 {
			avg := totalTriggerDuration / time.Duration(triggerDurationCount)
			summary.AvgTimeToTrigger = formatDuration(avg)
		}

		// Find nearest alert for stats
		var nearest *enrichedActiveAlert
		for i := range enrichedActive {
			if enrichedActive[i].DistancePct != nil {
				if nearest == nil || *enrichedActive[i].DistancePct < *nearest.DistancePct {
					nearest = &enrichedActive[i]
				}
			}
		}

		data.Stats = alertsToStatsData(summary, nearest)
		data.Active = alertsToActiveData(enrichedActive)
		data.Triggered = alertsToTriggeredData(enrichedTriggered)
	} else {
		data.Stats = alertsToStatsData(alertsSummary{}, nil)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.alertsTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render alerts page", "error", err)
	}
}

// ============================================================================
// Paper page: server-side rendering
// ============================================================================

func (d *DashboardHandler) servePaperPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.paperTmpl == nil {
		d.servePageFallback(w, "paper.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := PaperPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	engine := d.manager.PaperEngine()
	if engine != nil && email != "" {
		statusMap, err := engine.Status(email)
		if err == nil {
			enabled, _ := statusMap["enabled"].(bool)
			data.Enabled = enabled

			if enabled {
				data.Banner = paperStatusToBanner(statusMap)
				data.Stats = paperStatusToStats(statusMap)

				holdings, _ := engine.GetHoldings(email)
				positions, _ := engine.GetPositions(email)
				orders, _ := engine.GetOrders(email)
				data.Tables = paperDataToTables(holdings, positions, orders)
			} else {
				data.Banner = PaperBannerData{Enabled: false}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.paperTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render paper page", "error", err)
	}
}

// paperStatusToBanner converts paper status map to banner template data.
func paperStatusToBanner(status map[string]any) PaperBannerData {
	enabled, _ := status["enabled"].(bool)
	if !enabled {
		return PaperBannerData{Enabled: false}
	}
	initialCash, _ := status["initial_cash"].(float64)
	createdAt, _ := status["created_at"].(string)
	createdFmt := ""
	if createdAt != "" {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			createdFmt = fmtTimeDDMon(t)
		}
	}
	return PaperBannerData{
		Enabled:        true,
		InitialCashFmt: fmtINR(initialCash),
		CreatedFmt:     createdFmt,
	}
}

// paperStatusToStats converts paper status map to stats cards.
func paperStatusToStats(status map[string]any) PaperStatsData {
	cash, _ := status["cash"].(float64)
	totalValue, _ := status["total_value"].(float64)
	totalPnl, _ := status["total_pnl"].(float64)
	pnlPct, _ := status["pnl_pct"].(float64)

	return PaperStatsData{Cards: []UserStatCard{
		{Label: "Cash Balance", Value: fmtINR(cash)},
		{Label: "Portfolio Value", Value: fmtINR(totalValue)},
		{Label: "Total P&L", Value: fmtINR(totalPnl), Class: pnlClass(totalPnl)},
		{Label: "P&L %", Value: fmtPct(pnlPct), Class: pnlClass(pnlPct)},
	}}
}

// paperDataToTables converts paper engine data to tables template data.
func paperDataToTables(holdings, positions, orders any) PaperTablesData {
	var tables PaperTablesData

	// Holdings
	if holdingsList, ok := holdings.([]map[string]any); ok {
		for _, h := range holdingsList {
			ts, _ := h["tradingsymbol"].(string)
			ex, _ := h["exchange"].(string)
			qty := toInt(h["quantity"])
			avg := toFloat(h["average_price"])
			last := toFloat(h["last_price"])
			pnl := toFloat(h["pnl"])
			tables.Holdings = append(tables.Holdings, PaperHoldingRow{
				Tradingsymbol: ts, Exchange: ex, Quantity: qty,
				AvgPriceFmt: fmtPrice(avg), LastPriceFmt: fmtPrice(last),
				PnLFmt: fmtINR(pnl), PnLClass: pnlClass(pnl),
			})
		}
	}

	// Positions
	if posList, ok := positions.([]map[string]any); ok {
		for _, p := range posList {
			ts, _ := p["tradingsymbol"].(string)
			prod, _ := p["product"].(string)
			qty := toInt(p["quantity"])
			avg := toFloat(p["average_price"])
			last := toFloat(p["last_price"])
			pnl := toFloat(p["pnl"])
			tables.Positions = append(tables.Positions, PaperPositionRow{
				Tradingsymbol: ts, Product: prod, Quantity: qty,
				AvgPriceFmt: fmtPrice(avg), LastPriceFmt: fmtPrice(last),
				PnLFmt: fmtINR(pnl), PnLClass: pnlClass(pnl),
			})
		}
	}

	// Orders
	if ordersList, ok := orders.([]map[string]any); ok {
		for _, o := range ordersList {
			orderID, _ := o["order_id"].(string)
			ts, _ := o["tradingsymbol"].(string)
			txnType, _ := o["transaction_type"].(string)
			orderType, _ := o["order_type"].(string)
			qty := toInt(o["quantity"])
			price := toFloat(o["price"])
			status, _ := o["status"].(string)
			placedAt, _ := o["placed_at"].(string)

			sideBadge := "badge-green"
			if txnType == "SELL" {
				sideBadge = "badge-red"
			}
			statusBadge := "badge-amber"
			switch status {
			case "COMPLETE":
				statusBadge = "badge-green"
			case "REJECTED", "CANCELLED":
				statusBadge = "badge-red"
			}

			shortID := orderID
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			timeFmt := ""
			if t, err := time.Parse(time.RFC3339, placedAt); err == nil {
				timeFmt = fmtTimeHMS(t)
			}

			tables.Orders = append(tables.Orders, PaperOrderRow{
				OrderIDShort: shortID, Tradingsymbol: ts,
				TransactionType: txnType, SideBadge: sideBadge,
				OrderType: orderType, Quantity: qty,
				PriceFmt: fmtPrice(price), Status: status,
				StatusBadge: statusBadge, TimeFmt: timeFmt,
			})
		}
	}

	return tables
}

func toFloat(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

func toInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	}
	return 0
}

// ============================================================================
// Safety page: server-side rendering
// ============================================================================

func (d *DashboardHandler) serveSafetyPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.safetyTmpl == nil {
		d.servePageFallback(w, "safety.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := SafetyPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	// Build safety data from riskguard
	guard := d.manager.RiskGuard()
	if guard == nil {
		safetyData := map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		}
		data.Freeze = safetyToFreezeData(safetyData)
		data.Limits = safetyToLimitsData(safetyData)
		data.SEBI = safetyToSEBIData(safetyData)
	} else if email != "" {
		status := guard.GetUserStatus(email)
		limits := guard.GetEffectiveLimits(email)

		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		sessionActive := hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		_, hasCreds := d.manager.CredentialStore().Get(email)

		safetyData := map[string]any{
			"enabled": true,
			"status":  status,
			"limits": map[string]any{
				"max_single_order_inr":  limits.MaxSingleOrderINR,
				"max_orders_per_day":    limits.MaxOrdersPerDay,
				"max_orders_per_minute": limits.MaxOrdersPerMinute,
				"duplicate_window_secs": limits.DuplicateWindowSecs,
				"max_daily_value_inr":   limits.MaxDailyValueINR,
			},
			"sebi": map[string]any{
				"static_egress_ip": true,
				"session_active":   sessionActive,
				"credentials_set":  hasCreds,
				"order_tagging":    true,
				"audit_trail":      d.auditStore != nil,
			},
		}
		data.Freeze = safetyToFreezeData(safetyData)
		data.Limits = safetyToLimitsData(safetyData)
		data.SEBI = safetyToSEBIData(safetyData)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.safetyTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render safety page", "error", err)
	}
}

// ============================================================================
// Fragment endpoints for htmx auto-refresh
// ============================================================================

// servePortfolioFragment renders just the portfolio stats + holdings + positions for htmx refresh.
func (d *DashboardHandler) servePortfolioFragment(w http.ResponseWriter, r *http.Request) {
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, tokenValid := d.userContext(r)
	statusResp := d.buildUserStatus(email)

	alertCount := 0
	if email != "" {
		for _, a := range d.manager.AlertStore().List(email) {
			if !a.Triggered {
				alertCount++
			}
		}
	}

	var portfolio portfolioResponse
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
			holdings, herr := client.GetHoldings()
			positions, perr := client.GetPositions()
			if herr == nil && perr == nil {
				portfolio = d.buildPortfolioResponse(holdings, positions)
			}
		}
	}

	stats := portfolioToStatsData(statusResp, portfolio, alertCount)
	holdingsData := portfolioToHoldingsData(portfolio.Holdings)
	positionsData := portfolioToPositionsData(portfolio.Positions)

	// Market
	var market MarketBarData
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
			ohlcData, err := client.GetOHLC("NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX")
			if err == nil {
				indices := make(map[string]any, len(ohlcData))
				for k, v := range ohlcData {
					change := v.LastPrice - v.OHLC.Close
					changePct := 0.0
					if v.OHLC.Close > 0 {
						changePct = (change / v.OHLC.Close) * 100
					}
					indices[k] = map[string]any{
						"last_price": v.LastPrice,
						"change":     math.Round(change*100) / 100,
						"change_pct": math.Round(changePct*100) / 100,
					}
				}
				market = marketIndicesToBarData(indices)
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!-- portfolio fragment -->")

	// Render market bar
	if html, err := renderUserFragment(d.fragmentTmpl, "user_market_bar", market); err == nil {
		fmt.Fprint(w, html)
	}

	// Render stat cards
	fmt.Fprint(w, `<div class="stats-grid" id="statusCards">`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_stats", stats); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `</div>`)

	// Render holdings
	fmt.Fprint(w, `<div class="section-header">Holdings</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_holdings", holdingsData); err == nil {
		fmt.Fprint(w, html)
	}

	// Render positions
	fmt.Fprint(w, `<div class="section-header">Positions</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_positions", positionsData); err == nil {
		fmt.Fprint(w, html)
	}
}

// serveSafetyFragment renders safety partials for htmx refresh.
func (d *DashboardHandler) serveSafetyFragment(w http.ResponseWriter, r *http.Request) {
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, _ := d.userContext(r)
	guard := d.manager.RiskGuard()

	var safetyData map[string]any
	if guard == nil {
		safetyData = map[string]any{
			"enabled": false,
			"message": "RiskGuard is not enabled on this server.",
		}
	} else if email != "" {
		status := guard.GetUserStatus(email)
		limits := guard.GetEffectiveLimits(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		sessionActive := hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		_, hasCreds := d.manager.CredentialStore().Get(email)
		safetyData = map[string]any{
			"enabled": true,
			"status":  status,
			"limits": map[string]any{
				"max_single_order_inr":  limits.MaxSingleOrderINR,
				"max_orders_per_day":    limits.MaxOrdersPerDay,
				"max_orders_per_minute": limits.MaxOrdersPerMinute,
				"duplicate_window_secs": limits.DuplicateWindowSecs,
				"max_daily_value_inr":   limits.MaxDailyValueINR,
			},
			"sebi": map[string]any{
				"static_egress_ip": true,
				"session_active":   sessionActive,
				"credentials_set":  hasCreds,
				"order_tagging":    true,
				"audit_trail":      d.auditStore != nil,
			},
		}
	}

	freeze := safetyToFreezeData(safetyData)
	limitsData := safetyToLimitsData(safetyData)
	sebiData := safetyToSEBIData(safetyData)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_freeze", freeze); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `<div class="section-header">Limit Utilization</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_limits", limitsData); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `<div class="section-header">SEBI Compliance</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_safety_sebi", sebiData); err == nil {
		fmt.Fprint(w, html)
	}
}

// servePaperFragment renders paper trading partials for htmx refresh.
func (d *DashboardHandler) servePaperFragment(w http.ResponseWriter, r *http.Request) {
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, _ := d.userContext(r)
	engine := d.manager.PaperEngine()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if engine == nil || email == "" {
		fmt.Fprint(w, `<div class="empty-state">Paper trading is not enabled.</div>`)
		return
	}

	statusMap, err := engine.Status(email)
	if err != nil {
		fmt.Fprint(w, `<div class="empty-state">Failed to load paper trading status.</div>`)
		return
	}

	enabled, _ := statusMap["enabled"].(bool)
	banner := paperStatusToBanner(statusMap)
	if fragment, err := renderUserFragment(d.fragmentTmpl, "user_paper_banner", banner); err == nil {
		_, _ = io.WriteString(w, fragment) // #nosec G705 -- html/template auto-escapes
	}

	if enabled {
		stats := paperStatusToStats(statusMap)
		fmt.Fprint(w, `<div class="stats-grid" id="statsGrid">`)
		if html, err := renderUserFragment(d.fragmentTmpl, "user_paper_stats", stats); err == nil {
			fmt.Fprint(w, html)
		}
		fmt.Fprint(w, `</div>`)

		holdings, _ := engine.GetHoldings(email)
		positions, _ := engine.GetPositions(email)
		orders, _ := engine.GetOrders(email)
		tables := paperDataToTables(holdings, positions, orders)
		if html, err := renderUserFragment(d.fragmentTmpl, "user_paper_tables", tables); err == nil {
			fmt.Fprint(w, html)
		}
	}
}

// ============================================================================
// Fallback for when templates fail to parse
// ============================================================================

func (d *DashboardHandler) servePageFallback(w http.ResponseWriter, filename string) {
	data, err := templates.FS.ReadFile(filename)
	if err != nil {
		http.Error(w, "failed to load page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// parseOrderParamsJSON parses order input params from JSON.
func parseOrderParamsJSON(raw string, oe *orderEntry) {
	if raw == "" {
		return
	}
	var params map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		return
	}
	if v, ok := params["tradingsymbol"].(string); ok {
		oe.Symbol = v
	}
	if v, ok := params["exchange"].(string); ok {
		oe.Exchange = v
	}
	if v, ok := params["transaction_type"].(string); ok {
		oe.Side = v
	}
	if v, ok := params["order_type"].(string); ok {
		oe.OrderType = v
	}
	if v, ok := params["quantity"].(float64); ok {
		oe.Quantity = v
	}
}
