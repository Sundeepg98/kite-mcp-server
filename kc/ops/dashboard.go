package ops

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
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

// DashboardHandler serves the per-user trading dashboard and its API endpoints.
type DashboardHandler struct {
	manager    *kc.Manager
	logger     *slog.Logger
	auditStore *audit.Store
}

// NewDashboardHandler creates a new DashboardHandler. The auditStore parameter
// can be nil if the audit trail feature is not enabled.
func NewDashboardHandler(manager *kc.Manager, logger *slog.Logger, auditStore *audit.Store) *DashboardHandler {
	return &DashboardHandler{
		manager:    manager,
		logger:     logger,
		auditStore: auditStore,
	}
}

// RegisterRoutes mounts all dashboard routes, protected by the provided auth middleware.
func (d *DashboardHandler) RegisterRoutes(mux *http.ServeMux, auth func(http.Handler) http.Handler) {
	wrap := func(f http.HandlerFunc) http.Handler { return auth(f) }
	mux.Handle("/dashboard", wrap(d.servePage))
	mux.Handle("/dashboard/activity", wrap(d.serveActivityPage))
	mux.Handle("/dashboard/api/activity", wrap(d.activityAPI))
	mux.Handle("/dashboard/api/activity/export", wrap(d.activityExport))
	mux.Handle("/dashboard/orders", wrap(d.serveOrdersPage))
	mux.Handle("/dashboard/alerts", wrap(d.serveAlertsPage))
	mux.Handle("/dashboard/api/orders", wrap(d.ordersAPI))
	mux.Handle("/dashboard/api/portfolio", wrap(d.portfolio))
	mux.Handle("/dashboard/api/alerts", wrap(d.alerts))
	mux.Handle("/dashboard/api/alerts-enriched", wrap(d.alertsEnrichedAPI))
	mux.Handle("/dashboard/api/status", wrap(d.status))
}

// writeJSON encodes data as JSON and writes it to the response writer.
func (d *DashboardHandler) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		d.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeJSONError writes a JSON error response with the given status code.
func (d *DashboardHandler) writeJSONError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{
		"error":   errorCode,
		"message": message,
	}); err != nil {
		d.logger.Error("Failed to encode JSON error response", "error", err)
	}
}

// servePage serves the embedded dashboard.html page.
func (d *DashboardHandler) servePage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("dashboard.html")
	if err != nil {
		http.Error(w, "failed to load dashboard page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// serveActivityPage serves the embedded activity.html page.
func (d *DashboardHandler) serveActivityPage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("activity.html")
	if err != nil {
		http.Error(w, "failed to load activity page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// activityAPI returns paginated, filterable audit trail entries for the authenticated user.
func (d *DashboardHandler) activityAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	if d.auditStore == nil {
		d.writeJSON(w, map[string]string{"error": "audit trail not enabled"})
		return
	}

	// Parse query params
	opts := audit.ListOptions{
		Limit:      intParam(r, "limit", 50),
		Offset:     intParam(r, "offset", 0),
		Category:   r.URL.Query().Get("category"),
		OnlyErrors: r.URL.Query().Get("errors") == "true",
	}
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}

	results, total, err := d.auditStore.List(email, opts)
	if err != nil {
		d.logger.Error("Failed to list audit entries", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Compute aggregate stats from the DB (not just the current page).
	var stats *audit.Stats
	stats, err = d.auditStore.GetStats(email, opts.Since)
	if err != nil {
		d.logger.Error("Failed to get audit stats", "error", err)
		// Non-fatal: return entries without stats.
	}

	d.writeJSON(w, map[string]any{
		"entries": results,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
		"stats":   stats,
	})
}

// activityExport streams audit trail entries as CSV or JSON for download.
func (d *DashboardHandler) activityExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" || d.auditStore == nil {
		http.Error(w, "not available", http.StatusBadRequest)
		return
	}

	// Parse format (csv or json)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}

	// Parse time range
	opts := audit.ListOptions{Limit: 10000} // cap at 10K rows per export
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}

	results, _, err := d.auditStore.List(email, opts)
	if err != nil {
		d.logger.Error("Failed to export activity", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=activity.json")
		if err := json.NewEncoder(w).Encode(results); err != nil {
			d.logger.Error("Failed to encode JSON export", "error", err)
		}
		return
	}

	// CSV export
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=activity.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"Time", "Tool", "Category", "Input", "Output", "Duration (ms)", "Error", "Error Message"})
	for _, e := range results {
		isErr := "false"
		if e.IsError {
			isErr = "true"
		}
		_ = cw.Write([]string{
			e.StartedAt.Format(time.RFC3339),
			e.ToolName,
			e.ToolCategory,
			e.InputSummary,
			e.OutputSummary,
			fmt.Sprintf("%d", e.DurationMs),
			isErr,
			e.ErrorMessage,
		})
	}
	cw.Flush()
}

// intParam parses an integer query parameter, returning defaultVal if missing, invalid, or negative.
func intParam(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

// --- Portfolio types ---

type holdingItem struct {
	Tradingsymbol      string  `json:"tradingsymbol"`
	Exchange           string  `json:"exchange"`
	Quantity           int     `json:"quantity"`
	AveragePrice       float64 `json:"average_price"`
	LastPrice          float64 `json:"last_price"`
	PnL                float64 `json:"pnl"`
	DayChangePercent   float64 `json:"day_change_percentage"`
	Product            string  `json:"product"`
}

type positionItem struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
	Product       string  `json:"product"`
}

type portfolioSummary struct {
	HoldingsCount  int     `json:"holdings_count"`
	TotalInvested  float64 `json:"total_invested"`
	TotalCurrent   float64 `json:"total_current"`
	TotalPnL       float64 `json:"total_pnl"`
	PositionsCount int     `json:"positions_count"`
	PositionsPnL   float64 `json:"positions_pnl"`
}

type portfolioResponse struct {
	Holdings []holdingItem    `json:"holdings"`
	Positions []positionItem  `json:"positions"`
	Summary  portfolioSummary `json:"summary"`
}

// --- Alerts types ---

type alertsResponse struct {
	Active         interface{} `json:"active"`
	Triggered      interface{} `json:"triggered"`
	ActiveCount    int         `json:"active_count"`
	TriggeredCount int         `json:"triggered_count"`
}

// --- Status types ---

type tokenStatus struct {
	Valid    bool   `json:"valid"`
	StoredAt string `json:"stored_at,omitempty"`
}

type credentialStatus struct {
	Stored bool   `json:"stored"`
	APIKey string `json:"api_key,omitempty"`
}

type tickerStatus struct {
	Running       bool `json:"running"`
	Subscriptions int  `json:"subscriptions"`
}

type statusResponse struct {
	Email       string           `json:"email"`
	KiteToken   tokenStatus      `json:"kite_token"`
	Credentials credentialStatus `json:"credentials"`
	Ticker      tickerStatus     `json:"ticker"`
}

// --- Handlers ---

// portfolio fetches holdings and positions from the Kite API for the authenticated user.
func (d *DashboardHandler) portfolio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	// Get credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}

	// Get token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	// Create kiteconnect client
	client := kiteconnect.New(credEntry.APIKey)
	client.SetAccessToken(tokenEntry.AccessToken)

	// Fetch holdings
	holdings, holdingsErr := client.GetHoldings()
	if holdingsErr != nil {
		d.logger.Error("Failed to fetch holdings", "email", email, "error", holdingsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings from Kite: "+holdingsErr.Error())
		return
	}

	// Fetch positions
	positions, positionsErr := client.GetPositions()
	if positionsErr != nil {
		d.logger.Error("Failed to fetch positions", "email", email, "error", positionsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch positions from Kite: "+positionsErr.Error())
		return
	}

	// Build response
	resp := d.buildPortfolioResponse(holdings, positions)
	d.writeJSON(w, resp)
}

// buildPortfolioResponse maps gokiteconnect holdings/positions to the dashboard response format.
func (d *DashboardHandler) buildPortfolioResponse(holdings kiteconnect.Holdings, positions kiteconnect.Positions) portfolioResponse {
	// Map holdings
	holdingItems := make([]holdingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		holdingItems = append(holdingItems, holdingItem{
			Tradingsymbol:    h.Tradingsymbol,
			Exchange:         h.Exchange,
			Quantity:         h.Quantity,
			AveragePrice:     h.AveragePrice,
			LastPrice:        h.LastPrice,
			PnL:              h.PnL,
			DayChangePercent: h.DayChangePercentage,
			Product:          h.Product,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		totalPnL += h.PnL
	}

	// Map positions (use Net positions for the dashboard view)
	positionItems := make([]positionItem, 0, len(positions.Net))
	var positionsPnL float64
	for _, p := range positions.Net {
		positionItems = append(positionItems, positionItem{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Quantity:      p.Quantity,
			AveragePrice:  p.AveragePrice,
			LastPrice:     p.LastPrice,
			PnL:           p.PnL,
			Product:       p.Product,
		})
		positionsPnL += p.PnL
	}

	return portfolioResponse{
		Holdings:  holdingItems,
		Positions: positionItems,
		Summary: portfolioSummary{
			HoldingsCount:  len(holdings),
			TotalInvested:  totalInvested,
			TotalCurrent:   totalCurrent,
			TotalPnL:       totalPnL,
			PositionsCount: len(positions.Net),
			PositionsPnL:   positionsPnL,
		},
	}
}

// alerts returns the authenticated user's price alerts, separated into active and triggered.
func (d *DashboardHandler) alerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	activeAlerts := make([]interface{}, 0)
	triggeredAlerts := make([]interface{}, 0)
	for _, a := range allAlerts {
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, a)
		} else {
			activeAlerts = append(activeAlerts, a)
		}
	}

	d.writeJSON(w, alertsResponse{
		Active:         activeAlerts,
		Triggered:      triggeredAlerts,
		ActiveCount:    len(activeAlerts),
		TriggeredCount: len(triggeredAlerts),
	})
}

// status returns the connection and auth health check for the authenticated user.
func (d *DashboardHandler) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	resp := statusResponse{
		Email: email,
	}

	// Check token
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	} else {
		resp.KiteToken = tokenStatus{Valid: false}
	}

	// Check credentials
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{
			Stored: true,
			APIKey: credEntry.APIKey,
		}
	} else {
		resp.Credentials = credentialStatus{Stored: false}
	}

	// Check ticker
	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err != nil {
		d.logger.Error("Failed to get ticker status", "email", email, "error", err)
		resp.Ticker = tickerStatus{Running: false, Subscriptions: 0}
	} else {
		resp.Ticker = tickerStatus{
			Running:       tickerSt.Running,
			Subscriptions: len(tickerSt.Subscriptions),
		}
	}

	d.writeJSON(w, resp)
}

// --- Orders P&L types ---

type orderEntry struct {
	OrderID      string   `json:"order_id"`
	Symbol       string   `json:"symbol"`
	Exchange     string   `json:"exchange"`
	Side         string   `json:"side"`
	Quantity     float64  `json:"quantity"`
	OrderType    string   `json:"order_type"`
	PlacedAt     string   `json:"placed_at"`
	Status       string   `json:"status"`
	FillPrice    *float64 `json:"fill_price"`
	CurrentPrice *float64 `json:"current_price"`
	PnL          *float64 `json:"pnl"`
	PnLPct       *float64 `json:"pnl_pct"`
	Error        string   `json:"error,omitempty"`
}

type ordersSummary struct {
	TotalOrders   int      `json:"total_orders"`
	Completed     int      `json:"completed"`
	TotalPnL      *float64 `json:"total_pnl"`
	WinningTrades int      `json:"winning_trades"`
	LosingTrades  int      `json:"losing_trades"`
}

type ordersResponse struct {
	Orders  []orderEntry  `json:"orders"`
	Summary ordersSummary `json:"summary"`
}

// serveOrdersPage serves the embedded orders.html page.
func (d *DashboardHandler) serveOrdersPage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("orders.html")
	if err != nil {
		http.Error(w, "failed to load orders page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// ordersAPI returns order entries with P&L enrichment from the Kite API.
func (d *DashboardHandler) ordersAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	if d.auditStore == nil {
		d.writeJSON(w, map[string]string{"error": "audit trail not enabled"})
		return
	}

	// Parse since param (default: 7 days ago)
	since := time.Now().AddDate(0, 0, -7)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	toolCalls, err := d.auditStore.ListOrders(email, since)
	if err != nil {
		d.logger.Error("Failed to list orders", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Build base order entries from audit trail
	entries := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		oe := orderEntry{
			OrderID:  tc.OrderID,
			PlacedAt: tc.StartedAt.Format(time.RFC3339),
		}

		// Parse symbol/exchange/side/order_type from input_params JSON
		if tc.InputParams != "" {
			var params map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(tc.InputParams), &params); jsonErr == nil {
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
		}

		entries = append(entries, oe)
	}

	// Try to enrich with Kite API data
	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken {
		client = kiteconnect.New(credEntry.APIKey)
		client.SetAccessToken(tokenEntry.AccessToken)
	}

	if client != nil {
		// Enrich each order with fill details from order history
		// Collect symbols for batched LTP lookup
		type ltpKey struct {
			exchange string
			symbol   string
		}
		ltpKeys := make(map[string]ltpKey) // "exchange:symbol" -> ltpKey
		for i := range entries {
			oe := &entries[i]
			history, histErr := client.GetOrderHistory(oe.OrderID)
			if histErr != nil {
				oe.Error = "order history: " + histErr.Error()
				continue
			}

			// Find the latest status entry in the order history
			if len(history) > 0 {
				latest := history[len(history)-1]
				oe.Status = latest.Status

				// Use symbol/exchange from order history if not set from params
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

				// Only set fill price for completed orders
				if latest.Status == "COMPLETE" && latest.AveragePrice > 0 {
					fp := latest.AveragePrice
					oe.FillPrice = &fp
					if latest.FilledQuantity > 0 {
						oe.Quantity = latest.FilledQuantity
					}

					// Queue for LTP lookup
					if oe.Exchange != "" && oe.Symbol != "" {
						key := oe.Exchange + ":" + oe.Symbol
						ltpKeys[key] = ltpKey{exchange: oe.Exchange, symbol: oe.Symbol}
					}
				}
			}
		}

		// Batch LTP lookup for all completed orders
		if len(ltpKeys) > 0 {
			instruments := make([]string, 0, len(ltpKeys))
			for k := range ltpKeys {
				instruments = append(instruments, k)
			}
			ltpMap, ltpErr := client.GetLTP(instruments...)
			if ltpErr != nil {
				d.logger.Error("Failed to get LTP for orders", "email", email, "error", ltpErr)
			} else {
				// Apply current prices and compute P&L
				for i := range entries {
					oe := &entries[i]
					if oe.FillPrice == nil || oe.Exchange == "" || oe.Symbol == "" {
						continue
					}
					key := oe.Exchange + ":" + oe.Symbol
					if quote, ok := ltpMap[key]; ok && quote.LastPrice > 0 {
						cp := quote.LastPrice
						oe.CurrentPrice = &cp

						// Direction: BUY = +1, SELL = -1
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
	}

	// Compute summary
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

	d.writeJSON(w, ordersResponse{
		Orders:  entries,
		Summary: summary,
	})
}

// --- Alerts enriched types ---

type enrichedActiveAlert struct {
	ID              string  `json:"id"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	Exchange        string  `json:"exchange"`
	Direction       string  `json:"direction"`
	TargetPrice     float64 `json:"target_price"`
	ReferencePrice  float64 `json:"reference_price,omitempty"`
	CurrentPrice    float64 `json:"current_price,omitempty"`
	DistancePct     float64 `json:"distance_pct,omitempty"`
	CreatedAt       string  `json:"created_at"`
}

type enrichedTriggeredAlert struct {
	ID                string  `json:"id"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	Exchange          string  `json:"exchange"`
	Direction         string  `json:"direction"`
	TargetPrice       float64 `json:"target_price"`
	ReferencePrice    float64 `json:"reference_price,omitempty"`
	TriggeredPrice    float64 `json:"triggered_price,omitempty"`
	TriggerDeltaPct   float64 `json:"trigger_delta_pct,omitempty"`
	CreatedAt         string  `json:"created_at"`
	TriggeredAt       string  `json:"triggered_at,omitempty"`
	TimeToTrigger     string  `json:"time_to_trigger,omitempty"`
	NotificationSentAt string `json:"notification_sent_at,omitempty"`
	NotificationDelay string  `json:"notification_delay,omitempty"`
}

type alertsSummary struct {
	ActiveCount      int    `json:"active_count"`
	TriggeredCount   int    `json:"triggered_count"`
	AvgTimeToTrigger string `json:"avg_time_to_trigger"`
}

type enrichedAlertsResponse struct {
	Active    []enrichedActiveAlert    `json:"active"`
	Triggered []enrichedTriggeredAlert `json:"triggered"`
	Summary   alertsSummary            `json:"summary"`
}

// formatDuration formats a time.Duration into a human-readable string like "5d 1h 32m".
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	secs := int(d.Seconds())
	if secs > 0 {
		return fmt.Sprintf("%ds", secs)
	}
	return "0s"
}

// serveAlertsPage serves the embedded alerts.html page.
func (d *DashboardHandler) serveAlertsPage(w http.ResponseWriter, r *http.Request) {
	data, err := templates.FS.ReadFile("alerts.html")
	if err != nil {
		http.Error(w, "failed to load alerts page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(data); err != nil {
		d.logger.Error("Failed to write response", "error", err)
	}
}

// alertsEnrichedAPI returns enriched alert data with lifecycle metrics and current prices.
func (d *DashboardHandler) alertsEnrichedAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	allAlerts := d.manager.AlertStore().List(email)

	// Separate active and triggered
	var activeAlerts, triggeredAlerts []*alertCopy
	for _, a := range allAlerts {
		ac := &alertCopy{
			ID:                 a.ID,
			Tradingsymbol:      a.Tradingsymbol,
			Exchange:           a.Exchange,
			Direction:          string(a.Direction),
			TargetPrice:        a.TargetPrice,
			ReferencePrice:     a.ReferencePrice,
			Triggered:          a.Triggered,
			CreatedAt:          a.CreatedAt,
			TriggeredAt:        a.TriggeredAt,
			TriggeredPrice:     a.TriggeredPrice,
			NotificationSentAt: a.NotificationSentAt,
		}
		if a.Triggered {
			triggeredAlerts = append(triggeredAlerts, ac)
		} else {
			activeAlerts = append(activeAlerts, ac)
		}
	}

	// Try to get a Kite client for LTP enrichment
	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt) {
		client = kiteconnect.New(credEntry.APIKey)
		client.SetAccessToken(tokenEntry.AccessToken)
	}

	// Batch LTP lookup for active alerts
	ltpMap := make(map[string]float64) // "exchange:symbol" -> last price
	if client != nil && len(activeAlerts) > 0 {
		instruments := make(map[string]bool)
		for _, a := range activeAlerts {
			key := a.Exchange + ":" + a.Tradingsymbol
			instruments[key] = true
		}
		instList := make([]string, 0, len(instruments))
		for k := range instruments {
			instList = append(instList, k)
		}
		ltpData, err := client.GetLTP(instList...)
		if err != nil {
			d.logger.Error("Failed to get LTP for alerts", "email", email, "error", err)
		} else {
			for k, v := range ltpData {
				if v.LastPrice > 0 {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	// Build enriched active alerts
	enrichedActive := make([]enrichedActiveAlert, 0, len(activeAlerts))
	for _, a := range activeAlerts {
		ea := enrichedActiveAlert{
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		key := a.Exchange + ":" + a.Tradingsymbol
		if cp, ok := ltpMap[key]; ok {
			ea.CurrentPrice = cp
			if cp > 0 {
				ea.DistancePct = math.Round(math.Abs(cp-a.TargetPrice)/cp*10000) / 100
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
			ID:             a.ID,
			Tradingsymbol:  a.Tradingsymbol,
			Exchange:       a.Exchange,
			Direction:      a.Direction,
			TargetPrice:    a.TargetPrice,
			ReferencePrice: a.ReferencePrice,
			TriggeredPrice: a.TriggeredPrice,
			CreatedAt:      a.CreatedAt.Format(time.RFC3339),
		}
		// Trigger delta percentage
		if a.TriggeredPrice > 0 && a.TargetPrice > 0 {
			et.TriggerDeltaPct = math.Round(math.Abs(a.TriggeredPrice-a.TargetPrice)/a.TargetPrice*10000) / 100
		}
		// Time to trigger
		if !a.TriggeredAt.IsZero() {
			et.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
			ttd := a.TriggeredAt.Sub(a.CreatedAt)
			et.TimeToTrigger = formatDuration(ttd)
			totalTriggerDuration += ttd
			triggerDurationCount++
		}
		// Notification delay
		if !a.NotificationSentAt.IsZero() {
			et.NotificationSentAt = a.NotificationSentAt.Format(time.RFC3339)
			if !a.TriggeredAt.IsZero() {
				nd := a.NotificationSentAt.Sub(a.TriggeredAt)
				et.NotificationDelay = formatDuration(nd)
			}
		}
		enrichedTriggered = append(enrichedTriggered, et)
	}

	// Compute summary
	summary := alertsSummary{
		ActiveCount:    len(enrichedActive),
		TriggeredCount: len(enrichedTriggered),
	}
	if triggerDurationCount > 0 {
		avg := totalTriggerDuration / time.Duration(triggerDurationCount)
		summary.AvgTimeToTrigger = formatDuration(avg)
	}

	d.writeJSON(w, enrichedAlertsResponse{
		Active:    enrichedActive,
		Triggered: enrichedTriggered,
		Summary:   summary,
	})
}

// alertCopy is an internal struct for processing alerts without importing the alerts package directly.
type alertCopy struct {
	ID                 string
	Tradingsymbol      string
	Exchange           string
	Direction          string
	TargetPrice        float64
	ReferencePrice     float64
	Triggered          bool
	CreatedAt          time.Time
	TriggeredAt        time.Time
	TriggeredPrice     float64
	NotificationSentAt time.Time
}
